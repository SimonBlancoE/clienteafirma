# 06 — Desktop application, preferences, CLI, massive signing, plugins, updater, installer/configurator

> Specification for a 1:1 Rust reimplementation of **Autofirma** (Spanish Government e-signature desktop client).
> Source of truth: the Java code base at `/home/octo/Projects/autofirma` (Maven multi-module, project version `1.9.1`).
> This document covers the **desktop application** (`afirma-simple`), its **preferences**, **command line**, **massive signing**,
> **plugins**, **updater**, the **installer-time configurator** and the **per-OS installers**. It is written so that the
> features can be reimplemented **without reading the Java code**; Java class names are given only for traceability.

## 0. Scope, conventions and module map

### 0.1 Out of scope (covered by other specs)

- The internals of the `afirma://` protocol, the local WebSocket/HTTP(S) servers and the wire format of protocol
  operations (`afirma-simple` package `es.gob.afirma.standalone.protocol`). This document only describes how they are
  *dispatched* at startup and how they interact with the UI, preferences and installer (TLS certificate, protocol
  handler registration, secure-domain whitelist).
- Cryptographic signature formats (CAdES, XAdES, PAdES, FacturaE, ODF, OOXML), triphase signing, batch signing
  protocol formats, keystore access internals and signature validation algorithms. Here we only describe which
  options the UI/CLI/preferences pass to them (the "extra params") and how results are presented.
- The legacy "Cliente @firma" desktop application (`afirma-standalone`, `afirma-standalone-installer`), the applet
  and MiniApplet modules (`afirma-ui-applet*`, `afirma-ui-miniapplet*`), and the server-side modules
  (`afirma-server-*`, `afirma-signature-*`).

### 0.2 Conventions used in this document

- `code` = exact literal (key, constant, path, command, value). Spanish UI texts are quoted as `"texto"` followed
  by their message key when known (e.g. `"Firmar"` (`SignPanel.45`)). Spanish (`es_ES`) is the reference language.
- **Quirk:** / **Gotcha:** mark legacy or surprising behaviour of the original that a reimplementation must
  consciously decide to replicate or fix.
- "Java class" references use the simple class name; the package of `afirma-simple` is
  `es.gob.afirma.standalone` (sub-packages `ui`, `ui.preferences`, `ui.restoreconfig`, `ui.pdf`, `ui.plugins`,
  `ui.tasks`, `signdetails`, `crypto`, `updater`, `so.macos`, `protocol`).
- `§N` refers to section N of this document.

### 0.3 Module map (what each in-scope Maven module provides)

| Module | Artifact name | Role |
|---|---|---|
| `afirma-simple` | `afirma-ui-simpleafirma` | The Autofirma desktop app: `main()` (`es.gob.afirma.standalone.SimpleAfirma`), GUI, CLI, protocol dispatch, preferences UI, restore-config, updater, signature viewer. |
| `afirma-core-massive` | `afirma-core-massive` | Massive (directory / multi-document) signing helpers and log. |
| `afirma-core-prefs` | `afirma-core-prefs` | `KeyStorePreferencesManager`: user/system preferences for keystores (registered PKCS#11 smart cards, etc.). |
| `afirma-ui-simple-configurator-common` | `afirma-ui-simpleafirma-configurator-common` | `PreferencesManager` (ALL app preference keys + defaults + locking), config import/export (plist / signed config), shared with the configurator. |
| `afirma-ui-simple-configurator` | `afirma-ui-simpleafirma-configurator` | Installer-time configurator (`AutofirmaConfigurator`): local CA + SSL certificate generation, trust-store installation, Firefox/Chrome NSS, uninstall. |
| `afirma-simple-plugins` | `afirma-ui-simpleafirma-plugins` | Plugin API. |
| `afirma-simple-plugins-manager` | `afirma-ui-simpleafirma-plugins-manager` | Plugin installation, loading, signature verification, permissions. |
| `afirma-simple-plugin-hash` (+ `afirma-simple-plugin-hash-exe`) | `afirma-ui-simpleafirma-plugin-hash` | Official plugin: file/directory hash creation & verification (+ Windows context menu registration). |
| `afirma-simple-plugin-validatecerts` | `afirma-ui-simpleafirma-plugin-validatecerts` | Official plugin: OCSP/CRL validation of the signing certificate. |
| `afirma-ui-core-jse` | `afirma-ui-core-jse` | Generic Swing dialogs (messages, confirmations, file choosers, errors). |
| `afirma-ui-core-jse-keystores` | `afirma-ui-core-jse-keystores` | Certificate selection dialog. |
| `afirma-simple-installer` | (not a Maven module) | NSIS/WiX/launch4j (Windows), DEB/RPM (Linux), Packages `.pkg` + launcher app (macOS) build material. |

### 0.4 Document map

| § | Topic |
|---|---|
| 1 | Application startup and invocation modes (args, protocol dispatch, logging, directories, L&F, proxy, error codes) |
| 2 | GUI: main window, screens and flows (sign panel, results, signature viewer/validator, about, menus) |
| 3 | GUI: PDF visible signature dialogs, certificate selection, keystores, generic dialogs |
| 4 | Preferences (all keys, defaults, UI location, locking for administrators, storage per OS, import/export) |
| 5 | Command line interface |
| 6 | Massive (directory / multi-file) signing |
| 7 | Plugins (architecture + hash and certificate-validation plugins, to become built-in features) |
| 8 | Updater (optional) |
| 9 | Installer and configurator per OS (local CA/TLS certificate, trust stores, browsers, protocol handler, file associations, context menus, uninstall) |
| 10 | Restore configuration feature |
| 11 | Internationalisation |
| 12 | Accessibility |
| 13 | Parity checklist |



### 0.5 Cross-cutting gotchas (read this first)

These are the behaviours most likely to surprise a reimplementer. Each is detailed (with the exact source of truth) in the section indicated.

1. **Invocation:** a bare file path argument (`autofirma file.pdf`) is *not* "open in GUI": it is an unknown CLI command (exit −1 → 255). There is no `-version`. Windows Explorer integration uses `Autofirma.exe sign -gui -i "%1"` and `verify -gui -i "%1"`; Linux and macOS have no file associations at all (§1.3, §5.1, §9).
2. **Single instance:** only the desktop GUI takes the lock `~/.afirma/Autofirma/.lock`; `afirma://` invocations and `sign -gui` bypass it; on macOS the launcher stub starts a new JVM per URL (§1.3, §1.9, §9.5.2).
3. **CLI:** everything (errors included) goes to stdout; errors exit −1; the console default digest is **SHA-512** while the GUI preference default is **SHA256**; `-format auto` only yields PAdES/XAdES/CAdES; `batchsign` discards its own result and exits 0 on most errors; responses are not XML-escaped (§5).
4. **`sign -gui` (Explorer "Firmar con Autofirma")** drops both the preference-derived signature parameters and `-config`, ignores non-`auto` `-format`, and forces SHA-512 unless `-algorithm` is given (§2.4.2, §5.9.2).
5. **Preferences layering:** reads resolve user → system → default for **every** key, including the admin lock `preferencesBlocked`; the lock only greys out controls. Shipped defaults for OOXML and ODF are **CAdES**. `allowShadowAttack=true` means "*do* run the PDF shadow-attack check". Misspelled admin keys `requireSignedPrerefences` / `certHashToSignedPrerefences` must be kept (and the signed-config check is inverted in Java) (§4).
6. **Remote/installer configuration** (`-config_path`, `-update_config`) is downloaded **without TLS validation** and never signature-checked; `configDate` uses the week-year pattern `YYYYMMdd` (§4.11, §9.6).
7. **Local TLS material:** CA `CN=Autofirma ROOT` + leaf `CN=127.0.0.1`, RSA-2048, SHA256withRSA, 3650 days, random signed 32-bit serial (may be negative), leaf without EKU; `autofirma.pfx`, password `654321`, alias and NSS nickname `SocketAutoFirma`; "Restore configuration" generates a leaf **without** `DNS:localhost` (§9.2, §10.4).
8. **No browser policies anywhere:** no Chrome/Edge policies (`AutoLaunchProtocolsFromOrigins`, `ExternalProtocolDialogShowAlwaysOpenCheckbox`, …) and no Firefox `policies.json`; only `security.enterprise_roots.enabled` in `user.js` (Windows/macOS) and `network.protocol-handler.*` default prefs (Linux packages; the RPMs omit `expose.afirma=false`) (§9.7).
9. **Windows trust:** the NSIS installer (crypt32) puts the CA in **LocalMachine ROOT**, not the configurator; Firefox gets the CA in only **one profile per Windows user**; registry `command` values have **unquoted** executable paths (§9.3).
10. **Linux trust:** the configurator only writes `script.sh` / `uninstall.sh` that the package scripts run as root; users are taken from `/etc/passwd` homes containing `home/`; snap Firefox replaces (not adds to) the classic profile; flatpak/XDG profiles are ignored; NSS DBs that do not exist yet are skipped; only the `.deb` installs the CA in the system store; several file-name case mismatches break cleanup (§9.4).
11. **macOS trust:** CA trusted as `trustRoot` and the leaf as `trustAsRoot` in the System keychain using the user's password piped to `sudo -S`; the configurator runs as root from `postinstall`, so other users need "Restore configuration" (§9.5, §10.8).
12. **Restore configuration** writes `security.enterprise_roots.enabled=false` by default (checkbox unchecked), its Linux protocol step always fails, its Linux root detection is broken and its macOS Firefox cleanup never matches (§10).
13. **Desktop multi-file ("massive") signing** is implemented in `afirma-simple`, not in `afirma-core-massive` (unused by the desktop app). Output name = `signer.getSignedName(name, "_signed")` (e.g. `doc_signed.pdf`, `doc.txt_signed.csig`, `doc.xml_signed.xsig`), sub-folders mirrored, collisions insert `(n)` before the last dot (e.g. `doc_signed(1).pdf`) unless `massiveOverride`; a wrong PIN restarts the whole loop (§6.1).
14. **Hash feature:** `checkdigest` exits 0 even on mismatch; the XML `hash` attribute is URL-safe Base64 while `.hashb64` is standard Base64; relative paths use the OS separator (documents are not portable across OSes) (§7.5).
15. **Secrets:** the proxy password is AES-encrypted with a hard-coded key/IV (and exported in `.afconfig`); a secure-domain entry `*` disables TLS validation for every host (§1.13, §4.12, §4.13).
16. **i18n:** the OS language is never used (default `es_ES` from built-in preferences); classpath bundles are ISO-8859-1 with `\uXXXX`; imported language packs are UTF-8; the massive and plugin bundles are Spanish-only (§11).
17. **Logging:** `~/.afirma/AUTOFIRMA.afirma.log.xml` (XML, 2 MiB, truncated at each start); CLI mode silences almost all logging (§1.8).
18. **Keyboard:** Ctrl/Cmd+A opens a file, Ctrl/Cmd+V opens "Ver firma", Ctrl/Cmd+C opens "Acerca de" — they shadow clipboard shortcuts (§2.12, §12.4).


## 1. Application startup and invocation modes

This section describes how the desktop application (`afirma-simple`, main class `es.gob.afirma.standalone.SimpleAfirma`) is launched, how it classifies its command line, what it initialises and in which order, the files/directories it uses, logging, splash/progress feedback, theming (Look&Feel, HDPI, high contrast), proxy and SSL-context set-up, help, macOS integration and the error-code catalogue. Command-line operations themselves are specified in §5, preferences keys in §4, the GUI screens in §2/§3, the updater in §8, the installer-side registration in §9, the afirma:// protocol internals in the protocol spec (another document).

### 1.1 Executables / launchers per OS

The Java code is a single JAR (`autofirma.jar`, manifest `Main-Class: es.gob.afirma.standalone.SimpleAfirma`, `Implementation-Title: es.gob.afirma`, `Application-Name: Autofirma`, `Specification-Version: 1.8`, no `SplashScreen-Image`). Each OS wraps it with a launcher:

| OS | Launcher | What it runs | Notes |
|---|---|---|---|
| Windows | `Autofirma.exe` (launch4j, `headerType=gui`) | `jar\autofirma.jar`, main `SimpleAfirma` | JRE search path `./jre;%JAVA_HOME%;%PATH%`, `minVersion 1.8.0`, 64-bit build requires 64-bit JRE. JVM options `-Xms512m -Xmx8g -Djdk.tls.maxHandshakeMessageSize=65536`. Native splash `splash.bmp` shown with `waitForWindow=true`, `timeout=10` s, `timeoutErr=false` (i.e. the splash disappears when the first Java window appears or after 10 s). `chdir=.`. File version `1.10.0.0`. |
| Windows | `AutofirmaCommandLine.exe` (launch4j, `headerType=console`) | same JAR but main class `es.gob.afirma.standalone.CommandLineLauncher` (bypasses `SimpleAfirma.main`, see §5) | JVM options `-Xms512m -Xmx8g` (no TLS handshake option). No splash. |
| Linux (deb) | `/usr/bin/autofirma` (bash) | `java -Djdk.tls.maxHandshakeMessageSize=65536 -jar /usr/lib/Autofirma/autofirma.jar "$@"` | Uses system `java`. |
| Linux (rpm) | generated by the spec | `java -Djdk.tls.maxHandshakeMessageSize=65536 -jar %{_libdir}/autofirma/autofirma.jar "$@"` | |
| Linux desktop entry | `afirma.desktop` | `Exec=/usr/bin/autofirma %u` (rpm: `Exec=java ... -jar ... %u`), `MimeType=x-scheme-handler/afirma;` | Only the URL scheme is registered; no file MIME associations on Linux. |
| macOS | Objective-C stub `Autofirma.app/Contents/MacOS/Autofirma` (`AppDelegate.m`) | `<bundle>/Contents/Resources/Home/bin/java -Xms1024M -Xmx2048M -Djdk.tls.maxHandshakeMessageSize=65536 --add-exports java.desktop/com.apple.eawt=ALL-UNNAMED -Dcom.apple.macos.useScreenMenuBar=true -Xdock:name=Autofirma -Xdock:icon=<bundle>/Contents/Resources/JAR/icon.icns -Djava.library.path=<bundle>/Contents/Resources/JAR -jar <bundle>/Contents/Resources/JAR/autofirma.jar [<url>]` | The stub `chdir`s to the user home, registers for the Apple Event `kInternetEventClass/kAEGetURL` (afirma:// URLs). On `applicationDidFinishLaunching` it launches Java with no argument; on a GetURL event it launches Java with the URL as single argument. stdout/stderr go to `/dev/null`. After launching it sleeps 5 s and terminates itself (`[NSApp terminate:nil]`). Each URL therefore spawns a **new** JVM. No "open file" Apple Event is handled. |

Windows shell registrations (written by the installer, §9) that invoke the GUI executable:

| Registry command | Resulting argv |
|---|---|
| `HKCR\*\shell\afirma.sign\command` = `<INSTDIR>\<PATH>\Autofirma.exe sign -gui -i "%1"` (unquoted exe path, verb label "Firmar con Autofirma") | `sign -gui -i <file>` → CLI command `sign` in GUI mode (§5): opens main window with the file pre-loaded |
| `HKCR\.csig\shell\Verify\command`, `HKCR\.xsig\shell\Verify\command` = `<INSTDIR>\<PATH>\Autofirma.exe verify -gui -i "%1"` | opens the signature viewer (`VisorFirma`) standalone |
| `HKCR\afirma\shell\open\command` = `<INSTDIR>\<PATH>\Autofirma.exe "%1"` | `afirma://...` URL → protocol mode |

Gotcha: a bare file path as first argument (e.g. "Open with…" in a file manager) is **not** supported: it is treated as an unknown CLI command (see 1.3). The reimplementation may add a "file argument → open in GUI" mode, but must keep the documented forms working.

### 1.2 `SimpleAfirma` static initialisation

Before `main` runs, the class static initialiser:

1. Installs the file logger: `LogManager.install(App.AUTOFIRMA)` (see 1.8). Failure only logs a SEVERE line.
2. Creates `PluginsManager(getPluginsDir())` (plugins directory, see 1.9) – no plugin loaded yet.
3. Defines `APPLICATION_HOME = <user.home>/.afirma/Autofirma`.

The constructor `new SimpleAfirma()` creates the main frame (`MainScreen`, a `JFrame`), the menu bar (`MainMenu`, see §2) and calls `XmlDSigProviderHelper.configureXmlDSigProvider()` (selects Apache Santuario XMLDSig provider, avoids `&#13;` line breaks in Base64 – crypto spec).

### 1.3 `main(String[] args)` – exact sequence

```
1  configureLog()                          // optional extra file log via -Dafirma_debug / -Dafirma_debug_level (1.8)
2  ProgressInfoDialogManager.init(args)    // decides whether the "progress splash" is used (1.11)
3  showProgressDialog("Cargando Autofirma")            // ProgressInfoDialog.5
4  locale := pref "default.locale" (fallback "es_ES" if null/empty); setDefaultLocale(locale)   // 1.10 / §11
5  LookAndFeelManager.applyLookAndFeel()   // 1.12
6  showProgressDialog("Configurando conexiones seguras")  // ProgressInfoDialog.4
   ProxyUtil.setProxySettings()            // 1.13; on any Throwable: log SEVERE and, only if GUI mode
                                           // (no args) and not headless, warning dialog SimpleAfirma.11
7  start thread SSLContextConfigurationTask   // 1.14 (kept in a static so others can join it)
8  if isUsingCommandLine(args) || headless:   CommandLineLauncher.main(args); return     // §5
9  printSystemInfo()                       // INFO log: version, DPI, OS, Java, arch, vendor, locale, memory
10 if macOS: set Dock icon (/resources/logo_cliente_256.png via com.apple.eawt.Application.setDockIconImage,
           falling back to java.awt.Taskbar.setIconImage); if os.name starts with "Mac OS X" and
           /System/Library/Frameworks/PCSC.framework/Versions/Current is a dir:
           System property sun.security.smartcardio.library=/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC
           (work-around JDK-8255877)
11 update check (§8): updatesEnabled := updatesEnabled && !Boolean(-Des.gob.afirma.doNotCheckUpdates)
                                        && !Boolean(env AUTOFIRMA_AVOID_UPDATE_CHECK)
           if updatesEnabled && pref checkForUpdates: Updater.checkForUpdates(null, sslTask)  (async)
12 try:
     if args[0] lowercase starts with "afirma://":            ---- PROTOCOL MODE ----
        ProtocolInvocationLauncher.initLoadKeyStoreTask()     // background keystore preload
        log URL; showProgressDialog("Procesando petición")    // ProgressInfoDialog.3
        ProtocolInvocationLauncher.launch(args[0])            // blocks for non-websocket modes
        showProgressDialog("Procesando petición")
        if !args[0].startsWith("afirma://websocket"): forceCloseApplication(0)   // Runtime.halt(0)
        (websocket: return from main; the JVM stays alive serving the socket)
     else if !isSimpleAfirmaAlreadyRunning():                  ---- DESKTOP GUI MODE ----
        showProgressDialog("Iniciando interfaz gráfica")      // ProgressInfoDialog.6 (never visible, see 1.11)
        if ConfigUpdaterManager.needCheckConfigUpdates(): thread { ConfigUpdaterManager.updatePrefsConfigFile() } (§4)
        saf := new SimpleAfirma()
        if OS not Windows and not macOS (i.e. Linux):
            JMulticardUtilities.configureJMulticard(pref enabledJmulticard)
            try early NSS preload: AOKeyStoreManagerFactory.getAOKeyStoreManager(MOZ_UNI, lib=null,
                 description="AFIRMA-NSS-KEYSTORE", pwc=null, parent=null); saf.setKeyStoreManager(ksm)
            (failure only logged; a later normal load is attempted)
        if Linux: set XToolkit field awtAppClassName = "Autofirma" (WM_CLASS, so the desktop icon matches)
        plugins: SimpleAfirma.getPluginsManager().getPluginsLoadedList()   // loads plugins (§7);
                 on error warning dialog SimpleAfirma.4 / title SimpleAfirma.48
        saf.initGUI(null, null)                                // 1.5
        checkJavaVersion(mainFrame)                            // 1.5
        CheckTrustKeyStoreTask(mainFrame).execute()            // 1.14
     else:                                                     ---- SECOND INSTANCE ----
        warning dialog SimpleAfirma.3 ("La aplicación ya se está ejecutando en otra ventana.\nÚnicamente se permite una instancia activa.")
        title SimpleAfirma.48 ("Advertencia"); forceCloseApplication(0)
   catch HeadlessException: log; CommandLineLauncher.main(args)          // GUI impossible → console
   catch Exception: log SEVERE "Error global en la aplicacion";
         if args[0] starts with "afirma://websocket": forceCloseApplication(-1)
```

Argument classification helpers (exact semantics):

| Helper | Definition |
|---|---|
| `isUsingCommandLine(args)` | `args != null && args.length > 0 && !args[0].toLowerCase().startsWith("afirma://")` |
| `isUsingGUI(args)` | `args == null || args.length == 0` (only used to decide whether to show the proxy error dialog) |
| `isHeadlessMode()` | JVM system property `java.awt.headless == "true"` |
| protocol | `args[0].toLowerCase().startsWith("afirma://")` (case-insensitive) |
| websocket keep-alive test | `args[0].startsWith("afirma://websocket")` (case-**sensitive**) |

Resulting invocation modes:

| argv | Mode |
|---|---|
| (none) | Desktop GUI (single instance). In a headless JVM: CLI → prints general syntax, exit 0. |
| `afirma://...` | Protocol mode (no single-instance lock, multiple JVMs may coexist with the GUI). Only arg[0] is used; further args ignored. Headless JVM → routed to CLI (and fails as unknown command). |
| `-help` | CLI general help (exit 0). Matching is `equalsIgnoreCase`. |
| `<command> ...` where command ∈ `listaliases`, `sign`, `cosign`, `countersign`, `verify`, `batchsign` (exact lowercase match after `toLowerCase()`) | CLI (§5). `sign -gui` / `verify -gui` open GUI windows instead of printing results. |
| `<plugin command> ...` (e.g. hash plugin commands, §7) | CLI dispatched to the plugin whose `info.json` declares that command (case-insensitive) and which has the `COMMANDS` permission. |
| anything else (incl. a plain file path, `-version`, macOS `-psn_*`) | CLI error "unknown command" (message `CommandLineLauncher.15`) + general syntax, exit status −1. |

There is **no** `-version` option. The version is visible in the window title (`"Autofirma v%0"`, key `SimpleAfirma.10`), the About dialog and the log.

Gotchas:
- `CommandLineLauncher.main` sets the level of loggers `java.util.prefs`, `es.gob.afirma`, `es.gob.jmulticard` to `OFF` and `org.slf4j.simpleLogger.defaultLogLevel=off`, so in CLI mode (including `sign -gui`) almost nothing reaches the log file either.
- The CLI path is taken *before* the update check, the single-instance check, plugin loading via `SimpleAfirma`, the Java-version check, the NSS pre-load and the trust-store check. `sign -gui` therefore opens a second main window even if a GUI instance is already running.
- In protocol mode the update check (§8) **does** run (with no parent window).

### 1.4 Protocol-mode dispatch (summary only)

`ProtocolInvocationLauncher.launch(url)` (protocol spec owns the details):

1. On macOS, replaces the system "About" handler (`OSXHandler.setAboutHandler`) so "About Autofirma" works while only the protocol UI is shown.
2. `url == null` → error `620012` (`REQUEST_URI_NOT_FOUND`); not starting with `afirma://` (case-sensitive) nor `getresult?` → error `620009` (`UNSUPPORTED_REQUEST_SCHEME`).
3. Applies pref `enabledJmulticard` (`JMulticardUtilities.configureJMulticard`).
4. Parses query parameters; `jvc` (JavaScript version code, default 1, minimum 1 → warning dialog `ProtocolLauncher.51/52` if lower), `v` (protocol version), `ports`, `idsession`, `mcv` (minimum client version), `dlgload` (show progress dialog, read earlier by `ProgressInfoDialogManager`).
5. Dispatch by prefix (both `afirma://op?` and `afirma://op/?` accepted):

| Prefix | Handler | Notes |
|---|---|---|
| `afirma://websocket?` | `AfirmaWebSocketServerManager.startService(channelInfo, version, asynchronous = jvc > 3)` | Default port `63117` if `ports` absent. Errors → error dialog + `Runtime.halt(0)`. Returns "OK"; JVM keeps running. |
| `afirma://service?` | `ServiceInvocationManager.startService` (legacy local TCP socket) | `ports` mandatory (`620013`). Blocks in the accept loop. |
| `afirma://batch?` | `ProtocolInvocationLauncherBatch` | XML or JSON batch (`jsonbatch` param), via intermediate server. |
| `afirma://selectcert?` | `ProtocolInvocationLauncherSelectCert` | |
| `afirma://save?` | `ProtocolInvocationLauncherSave` | |
| `afirma://signandsave?` | `ProtocolInvocationLauncherSignAndSave` | |
| `afirma://sign?`, `afirma://cosign?`, `afirma://countersign?` | `ProtocolInvocationLauncherSign` | |
| `afirma://load?` | `ProtocolInvocationLauncherLoad` | |
| other | error `600002` (`UNSUPPORTED_OPERATION`) | |

Supported protocol versions: `4.1`, `3`, `2`, `1`.

### 1.5 Desktop GUI start (`initGUI(preSelectedFile, signConfig)`)

1. `showDNIeScreen := preSelectedFile == null && !pref hideDnieStartScreen`; if true, also require that `TerminalFactory.getDefault().terminals().list()` is **non-empty** (any PC/SC reader present); any exception → false.
2. Window title := `"Autofirma v" + version` (`SimpleAfirma.10` = `Autofirma v%0`, version = `currentVersionText.<OS>` from `updater.properties`, currently `1.10`).
3. If DNIe screen: show `DNIeWaitPanel` (§2) in the main window (preferred size 780×580), set container accessible description `DNIeWaitPanel.3 + DNIeWaitPanel.7`. Events from the panel:
   - `PROP_DNIE_REJECTED` (button "Usar almacén por defecto" or Esc) → load default keystore, show sign panel.
   - `PROP_DNIE_REQUESTED` (button "Continuar con DNIe") → `SimpleKeyStoreManagerWorker(dnie=true, forced=ksManager!=null)`; on exception fall back to default keystore; then show sign panel.
   - `PROP_HELP_REQUESTED` (F1, not on macOS) → `showHelp("Autofirma.html")`.
4. Else: show `SignPanel` (§2), start default keystore loading in background (`SimpleKeyStoreManagerWorker(dnie=false, forced=false)`, wait cursor while scheduling; on scheduling failure error `SimpleAfirma.42`), install menu bar, and if `preSelectedFile != null` call `loadFileToSign(file, signConfig)` (errors → dialog `SimpleAfirma.0`).
   - If a keystore was already pre-loaded (Linux NSS preload) and pref `defaultKeystore` is `default`, the concurrent load is skipped.
5. `setKeyStoreManager(ksm)`: stores it and notifies the `SignPanel` (`notifyStoreReady()`); `null` → error dialog `SimpleAfirma.6` ("No se ha podido inicializar el almacén de claves.\nNo podrá realizar firmas electrónicas."), title `SimpleAfirma.7` ("Error").
6. Java version check (`checkJavaVersion`, Java-specific, can be dropped in Rust): if `java.version` does not start with `1.8`, `11.0`, `17.0`, `21`, `25` and pref `checkJavaVersion` is true → warning `SimpleAfirma.49/50` with checkbox `SimpleAfirma.51` ("No volver a mostrar") which sets `checkJavaVersion=false`; if version is supported and pref is false it is reset to true.
7. `CheckTrustKeyStoreTask` (background): tries to build the local WebSocket TLS server context (`SecureSocketUtils.getSecureSSLContext()`, i.e. loads the PKCS#12 SSL keystore created by the configurator, §9). On failure: error dialog `TrustedKeyStoreError.0` ("No se han encontrado las claves para la conexión segura con el navegador. Ejecute la función de restauración de la instalación desde el menú de herramientas de Autofirma para poder firmar.") with error code `200801`.

Keystore resolution when an operation needs it (`getAOKeyStoreManager()`): if none loaded, type := pref `defaultKeystore` (if not `default` and valid for the OS/Firefox present) else the OS default (`AOKeyStore.getDefaultKeyStoreTypeByOs`: Windows → Windows store `WINDOWS`, macOS → Apple keychain `APPLE`, Linux → shared system NSS DB `SHARED_NSS` (`~/.pki/nssdb`); note that on Linux the desktop GUI normally ends up using the Firefox store `MOZ_UNI` because of the early preload in 1.3 when `defaultKeystore=default`, see §3.10.3); for PKCS12/PKCS11 the library/file path comes from pref `defaultLocalKeystorePath`. Errors: `SimpleAfirma.54` (bad configured store), `SimpleAfirma.56` (read error) or cancellation → fall back to OS default store; failure of the fallback → `SimpleAfirma.6`. If a keystore is loaded but the certificate-selection dialog last selected a different store (`KeyStorePreferencesManager.getLastSelectedKeystore()`), that store is (re)loaded (cancellation message `SimpleAfirma.57`). Keystore details: §3/§4.

### 1.6 Main window

| Aspect | Behaviour |
|---|---|
| Class | `MainScreen` (`JFrame`), content = `JScrollPane` (unit increment 30 px both axes) wrapping the current panel; panels are swapped with `replaceShowingPanel(panel)` followed by `pack()` |
| Size | preferred viewport 780×580 (`DEFAULT_WINDOW_WIDTH/HEIGHT`), `pack()`, centred (`setLocationRelativeTo(null)`); **maximised** if screen height ≤ 600 px (`LookAndFeelManager.needMaximizeWindow()`). No size/position persistence. |
| Background | `LookAndFeelManager.DEFAULT_COLOR` unless Windows high contrast |
| Icons | `/resources/logo_cliente_{16,24,32,48,128,256,512}.png` (`DesktopUtil.getIconImages()`); dialogs use `logo_cliente_24.png` |
| Title | `Autofirma v1.10`; after a signature: `Autofirma v1.10 - <signature file name>`; after multi-file signing: `Autofirma v1.10 - <output dir absolute path>` |
| macOS | root-pane client property `Window.documentFile` set to the signature file/output dir (proxy icon), `null` on the sign screen |
| Close | `DO_NOTHING_ON_CLOSE`; window-closing → `askForClosing()` |
| Screens | DNIe wait → Sign panel → result (single: `SignDetailPanel`; multiple: `SignResultListPanel`) → back to sign panel (`loadMainApp()`); see §2 |

`askForClosing()`: if pref `omitAskOnClose` is true → exit 0 immediately. Otherwise confirm dialog (YES/NO, warning icon, title `SimpleAfirma.48` "Advertencia") whose content is `ClosePanel`: label `SimpleAfirma.47` ("¿Desea cerrar la aplicación de firma?") + checkbox `ClosePanel.0` ("No volver a mostrar este mensaje", mnemonic `m`) bound to `omitAskOnClose` — Quirk: the checkbox writes the preference immediately when toggled, even if the user then answers "No". YES → `closeApplication(0)` (dispose window, `System.exit(0)`).

### 1.7 Exit paths and exit codes

| Situation | Mechanism | Code |
|---|---|---|
| GUI closed (menu "Salir" Alt+F4, window close, macOS Quit) after confirmation | `System.exit` (shutdown hooks run, lock file deleted) | 0 |
| Second GUI instance | warning dialog then `Runtime.halt` | 0 |
| Protocol request (non-websocket) finished | `Runtime.halt` (no shutdown hooks) | 0 |
| Protocol websocket: unsupported version / cannot open port / SSL keystore missing | error dialog, `Runtime.halt` | 0 |
| Uncaught exception during websocket start-up | `Runtime.halt` | −1 |
| Language change "restart now" (§11) | spawn new process, `System.exit` | 0 |
| CLI success / `-help` | `System.exit` | 0 |
| CLI error (bad params, unknown command, operation error) | `System.exit` | −1 (shell sees 255 on Unix) |
| `sign -gui`, `verify -gui` | process keeps running with the window; exit as GUI | 0 |

### 1.8 Logging

Java `java.util.logging`; all application loggers are named `es.gob.afirma` (children of `es.gob`).

| Item | Value |
|---|---|
| Main log file | `<user.home>/.afirma/AUTOFIRMA.afirma.log.xml` (`LogManager`: pattern `%h/.afirma/%a.afirma.log.xml`, `%a` = `AUTOFIRMA`; configurator uses `AUTOFIRMA_CONFIGURATOR`). Directory created if missing. |
| Format | `java.util.logging.XMLFormatter` (FileHandler default) – XML `<record>` elements |
| Rotation | max 2 MiB (`1024*1024*2`), 1 generation, `append=false` → **truncated at every start**. If the file is locked by another running instance the JDK appends a unique suffix (`.1`, …). |
| Handler attached to | logger `es.gob` |
| Level | JRE default (`INFO`); can be changed with `-Dafirma_debug_level=<LEVEL>` (any `java.util.logging.Level` name, applied to logger `es.gob.afirma`) |
| Optional second file | `-Dafirma_debug=<path>`: extra `FileHandler(path, 10 MiB, 3 files)` with plain formatter `"<millis>: <LEVEL>: <message>\n"` |
| Console | root `ConsoleHandler` (stderr) as per JRE defaults |
| Privacy | paths are logged through `LoggerUtil.getCleanUserHomePath()` (replaces user home) and `getTrimStr()` (truncates URLs) |
| Start-up info line | `printSystemInfo()` logs version, Windows DPI (`wmic desktopmonitor get PixelsPerXLogicalInch`, 0 elsewhere), `os.name`, `os.version`, `java.version`, JRE arch, `java.vm.vendor`, default locale, total/max/free memory in MB |

`LogManager.getLogFile()` (used to attach the log to error reports) closes the handler, reads the file and re-opens a handler.

Recommendation for the Rust port: keep a per-user rotating log file in the app data directory, keep the `afirma_debug`-style switches as env vars/CLI flags, and never log full user paths.

### 1.9 Application directories and files

| Purpose | Path | Notes |
|---|---|---|
| App data (`APPLICATION_HOME`) | `<home>/.afirma/Autofirma` (all OSes) | created on demand |
| Single-instance lock | `<home>/.afirma/Autofirma/.lock` | `RandomAccessFile(rw).getChannel().tryLock()`; held for the GUI lifetime; released and **deleted** by a shutdown hook. Lock failure (exception) → treated as "not running". Only the desktop GUI mode takes the lock. |
| Extracted help | `<home>/.afirma/Autofirma/help/` + `help.version` | 1.15 |
| Help launcher page | `<java.io.tmpdir>/local_launcher.html` | 1.15 |
| Log | `<home>/.afirma/AUTOFIRMA.afirma.log.xml` | 1.8 |
| Installation directory (`DesktopUtil.getApplicationDirectory()`) | directory containing `autofirma.jar` (Windows: install dir, Linux `/usr/lib/Autofirma`, macOS `Autofirma.app/Contents/Resources/JAR`). Under Java Web Start (JNLP) the "alternative" dir is used instead (Windows/macOS) or `java.io.tmpdir`. | The SSL keystore/CA files generated by the configurator live here (§9). |
| "Alternative" directory (`DesktopUtil.getAlternativeDirectory()`) | Windows `%ALLUSERSPROFILE%\Autofirma` (e.g. `C:\ProgramData\Autofirma`); Linux `<home>/.afirma/Autofirma`; macOS `$HOME/Library/Application Support/Autofirma`; other OS: none → installation dir | |
| Plugins | `<alternative dir>/plugins` (§7) | |
| Imported languages | `<alternative dir>/languages/<ll_CC>/` (§11) | |
| User preferences | `java.util.prefs` user node `/es/gob/afirma/standalone/ui/preferences` (§4) | |
| Updater last check | `java.util.prefs` user node `es/gob/afirma/standalone`, key `lastCheckDate` (§8) | |

Unused helper (do not port unless wanted): `DesktopUtil.get/setAutoStartEnabled` (Windows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `Autofirma` — the "enable" path even writes `c:\windows\system32\winver.exe`, clearly a stub). `SimpleAfirma.getIp()` (calls `http://checkip.amazonaws.com`) is never called.

### 1.10 System properties and environment variables

Read by the application:

| Name | Kind | Effect |
|---|---|---|
| `afirma_debug` | JVM prop | path of an extra debug log file (1.8) |
| `afirma_debug_level` | JVM prop | log level for `es.gob.afirma` |
| `es.gob.afirma.doNotCheckUpdates` | JVM prop (`true`) | disables update check (§8) |
| `AUTOFIRMA_AVOID_UPDATE_CHECK` | env (`true`) | disables update check (§8) |
| `java.awt.headless` | JVM prop | forces CLI mode |
| `AFIRMA_NSS_DISABLE_DNIE_NATIVE_DRIVER`, `AFIRMA_NSS_DISABLE_CERES_NATIVE_DRIVER` | env | if either is set, the "enable JMulticard" preference is shown as system-controlled (§4) |
| `es.gob.afirma.protocolinvocation.HeadLess` | JVM prop | protocol errors not shown in dialogs (protocol spec) |
| `AFIRMA_SHOW_DATA_TO_SIGN` | JVM prop | protocol debug: show data before signing (protocol spec) |
| `ALLUSERSPROFILE`, `HOME`, `USER`, `windir` | env | directory resolution / restore-config |

Set by the application at runtime:

| Property | Value / source |
|---|---|
| `sun.security.smartcardio.library` | macOS PCSC path (1.3 step 10) |
| `es.gob.afirma.keystores.mozilla.disableDnieNativeDriver`, `es.gob.afirma.keystores.mozilla.disableCeresNativeDriver` | `true` when pref `enabledJmulticard` is false; cleared otherwise |
| `disableSslChecks` | `!secureConnections` (pref) – `HttpManager.setSecureConnections` |
| `secureDomainsList` | pref `secureDomainsList` (cleared if empty) |
| `blockAutoImportTrustedCerts` | `true` unless admin prefs allow personal truststore **and** auto-import (1.14) |
| `http(s).proxyHost/Port`, `ftp.proxHost` [sic], `ftp.proxyPort`, `socksProxyHost/Port`, `*.nonProxyHosts`, `socksNonProxyHosts` | custom proxy (1.13) |
| `websockets.optimizedForVdi` | pref `vdiOptimization` (protocol spec) |
| `apple.awt.*`, `apple.laf.useScreenMenuBar=true` | macOS (1.12) |
| `org.slf4j.simpleLogger.defaultLogLevel=off` | CLI mode |

### 1.11 Splash / progress feedback

- Windows only: native launch4j splash `splash.bmp` until the first window appears (max 10 s).
- Java side: `ProgressInfoDialogManager` + `ProgressInfoDialog` – an undecorated, non-resizable rounded (radius 20) white panel with a centred 18 pt label, centred on screen, used as a "loading" indicator **only in protocol mode**:
  - `init(args)`: if `args[0]` starts with `afirma://`, parse the URL; if it has parameter `dlgload`, `show = Boolean.parseBoolean(dlgload)` else `show = true`. Any non-protocol invocation → `show = false`.
  - The dialog is additionally gated by pref `enableProgressDialog` (default `true`).
  - Messages (`simpleafirmamessages`): `ProgressInfoDialog.5` "Cargando Autofirma", `.4` "Configurando conexiones seguras", `.3` "Procesando petición", `.6` "Iniciando interfaz gráfica", `.2` "Cargando almacenes de claves", `.0` "Comprobando firmas anteriores", `.1` "Ejecutando firma" (the last three are used by protocol handlers). `hideProgressDialog()` hides it.
- No Java `SplashScreen-Image` is used (an unused `splash.gif` resource exists).

### 1.12 Look & Feel, HDPI and theming (`LookAndFeelManager`, `HDPIManager`)

Computed once (static):

| Constant | Computation |
|---|---|
| `DEFAULT_COLOR` | `UIManager.getColor("window")` or RGB(238,238,238) on error/null |
| `WINDOWS_HIGH_CONTRAST` | AWT desktop property `win.highContrast.on` is `Boolean.TRUE` (Windows only) |
| `SECUNDARY_COLOR` | black if high contrast, else white |
| `LARGE_FONT` | Windows: desktop property `win.defaultGUI.font.height` > 13; **Linux: always true**; others false |
| `GNOME_DARK_MODE` | Linux only: (`echo $XDG_CURRENT_DESKTOP` contains "gnome" or `echo $XDG_DATA_DIRS \| grep -Eo 'gnome'` or `ps -e \| grep -E -i "gnome"`) and `gsettings get org.gnome.desktop.interface gtk-theme` contains "dark". Quirk: the commands are run with `Runtime.exec` (no shell), so the `echo $VAR`/pipe variants never work; detection is effectively broken. |
| `TRANSPARENT_COLOR` | RGBA(255,255,255,0) |

`applyLookAndFeel(force=false)` (idempotent):

1. `useSystemLookAndFeel = WINDOWS_HIGH_CONTRAST || LARGE_FONT || GNOME_DARK_MODE`.
2. If not system L&F: `UIManager` puts `Button.defaultButtonFollowsFocus=true` and backgrounds (`RootPane`, `TextPane`, `TextArea`, `InternalFrameTitlePane`, `InternalFrame`, `Label`, `PopupMenuSeparator`) = `DEFAULT_COLOR`.
3. `JFrame/JDialog.setDefaultLookAndFeelDecorated(true)`.
4. macOS: `OptionPane.background`, `Panel.background` = `DEFAULT_COLOR`; system props `apple.awt.brushMetalLook=true`, `apple.awt.antialiasing=true`, `apple.awt.textantialiasing=true`, `apple.awt.rendering=quality`, `apple.awt.graphics.EnableQ2DX=true`, `apple.awt.graphics.EnableDeferredUpdates=true`, `apple.laf.useScreenMenuBar=true` (default Aqua L&F kept, menu in the screen menu bar).
5. else Windows and `HDPIManager.isHDPIDevice()` → **Metal** L&F.
6. else if `useSystemLookAndFeel` → system L&F (Windows classic/GTK).
7. else → **Nimbus**.

Effective result: Windows normal → Nimbus; Windows high-contrast or large fonts → native Windows L&F; Linux → GTK (always, because `LARGE_FONT` is forced); macOS → Aqua.

`HDPIManager.isHDPIDevice()` (Windows): runs `wmic csproduct get name`, takes the first non-empty line that is not `Name`, trims it and compares it **exactly** with each line of the bundled resource `/lookandfeel/hdpi_devices`: `Surface Pro 3`, `Surface 3`, `HP Elite x2 1012 G1`.

Rust guidance: use the native toolkit theme, follow OS dark mode/high contrast and OS scaling factor (per-monitor DPI) instead of these heuristics; keep the "≤ 600 px tall screen → maximise" rule.

### 1.13 Proxy application at runtime (`ProxyUtil`, `ProxyConfig`)

Preference keys are listed in §4 (`proxyType`, `proxySelected`, `proxyHost`, `proxyPort`, `proxyUsername`, `proxyPassword`, `proxyExcludedUrls`). `setProxySettings()` is called at start-up and again when the proxy dialog is accepted.

1. Remember the JVM's original `ProxySelector` the first time.
2. Proxy type resolution:
   - `proxyType` (default `NONE` in `preferences.properties`) parsed as enum `NONE | SYSTEM | CUSTOM`; invalid value → `NONE` (warning).
   - Legacy (only if `proxyType` is null): `proxySelected=false` → `SYSTEM`; `proxySelected=true` and host+port non-blank → `CUSTOM`; else `NONE`.
3. Selector per type:
   - `NONE`: selector returning `Proxy.NO_PROXY` for every URI (direct connections).
   - `SYSTEM`: auto-detected with the *proxy-vole* library: temporarily set a no-proxy default selector, `ProxySearch` with strategies `OS_DEFAULT` then `BROWSER` (Windows registry/WinHTTP incl. PAC/WPAD, macOS system settings, GNOME/KDE/env vars on Linux, Firefox/IE settings), restore. If nothing is found the result may be null → "no proxy" is logged and the default selector is left untouched.
   - `CUSTOM`: set JVM properties `http.proxyHost`, `http.proxyPort`, `https.proxyHost`, `https.proxyPort`, `ftp.proxHost` (typo in original), `ftp.proxyPort`, `socksProxyHost`, `socksProxyPort` to host/port; if `proxyExcludedUrls` non-blank (trimmed): `http.nonProxyHosts`, `https.nonProxyHosts`, `ftp.nonProxyHosts`, `socksNonProxyHosts` (Java syntax: `|`-separated host patterns with `*` wildcards). If username **and** password are non-blank, decrypt the password and install a global `Authenticator` answering only `RequestorType.PROXY` requests. The JVM's original selector is returned (which honours the properties).
4. `ProxySelector.setDefault(selector)`; logs which proxy would be used for `http://www.theregister.co.uk` and `https://firmaelectronica.gob.es/`.

Proxy password storage (`cipherPassword` / `decipherPassword`):

- Primary: AES/CBC/PKCS5Padding, key = Base64 `3zevqLjBQTqWKCDEev3kNyjRWQpeuKe3xYlcdGmBYZE=` (32 bytes, AES-256), IV = Base64 `NKAe+g8shVCYWEEhLNPU0A==`; plaintext = UTF-8 password; output = **URL-safe Base64** (`-`/`_`) with padding.
- Fallback (if AES fails, or to read legacy values): DES/ECB/NoPadding with key ASCII `8W{t2r,B`; data zero-padded to a multiple of 8; output = `"<padLen>." + urlSafeBase64(cipher)` where `padLen = (8 - len%8) % 8`; decryption strips `padLen` trailing bytes when the 2nd char is `.`.
- Decryption accepts URL-safe Base64 (replaces `_`→`/`, `-`→`+`).
- This is obfuscation (fixed keys in the binary), not security. Rust port: must be able to read existing values (same keys) for migration; may store new values in the OS keychain.

`ProxyUtil.getDefaultProxyToUrl(url)` returns the first system-detected proxy for a URL (used by the proxy dialog "Autodetectar"/"Verificar conexión", §4). Error code `200702` (`NO_DETECTED_PROXIES`) and `521010` (`INVALID_PROXY_CONFIG`) are used by that dialog.

### 1.14 Secure-connection set-up (`SSLContextConfigurationTask`, `HttpManager`)

Background thread started at step 7 (the updater joins it before connecting):

1. `secureConnections` pref (default `true`) → system property `disableSslChecks = !secureConnections` (when true, the HTTP client trusts any certificate/hostname).
2. `secureDomainsList` pref → system property `secureDomainsList` or cleared. Semantics (in `UrlHttpManagerImpl`): comma-separated host patterns for which TLS certificate/hostname validation is **disabled** ("trusted" domains whose certificate may not chain to a trusted root): `*x*` → host contains `x`; `*x` → host ends with `x`; `x*` → host starts with `x`; `x` → host equals `x` (no trimming of spaces).
3. `allowPersonalTruststore = admin pref` `PreferencesManager.ADMIN_PREFERENCE_ALLOW_PERSONAL_TRUSTSTORE`, `allowAutoImport = allowPersonalTruststore && ADMIN_PREFERENCE_ALLOW_AUTO_IMPORT_TRUSTED_CERTS`; if not allowed → system property `blockAutoImportTrustedCerts=true` (the HTTP client then never offers to import an untrusted server certificate).
4. If `secureConnections`: if personal truststore allowed, `SslSecurityManager.configureAfirmaTrustManagers()` (JVM cacerts + Autofirma's own trusted-certificates store, managed in "Certificados de confianza", §4); then a dummy HTTPS connection to `https://test.conexion.gob.es/` with 100 ms connect timeout (work-around: first connection after changing trust managers may fail). Exceptions are stored (`getException()`).

`HttpManager` is the HTTP client façade used by the app (updater, remote config, policies): it applies the two system properties above at construction and, on `SSLHandshakeException`, uses `SSLErrorProcessor` which may ask the user to trust and import the server certificate into Autofirma's truststore (unless blocked/headless). Truststore details belong to §4/§3.

### 1.15 Help system (`SimpleAfirma.showHelp`, `HelpResourceManager`)

Help is a set of local HTML pages opened in the system browser.

1. `helpDir = <home>/.afirma/Autofirma/help`.
2. If `helpDir/help.version` does not exist or its content ≠ `currentVersionText` (`1.10`): extract every resource listed (one relative path per line) in the bundled index `help/fileslist.txt` from the JAR's `help/` folder into `helpDir`, creating subdirectories, **except** files that already exist and belong to an imported language (path starts with `<locale>/` or is named `index_<locale>.html` for an imported locale). Then write `help.version` with the version text.
3. `locale = pref default.locale` (fallback `es_ES`).
4. If `<installation dir>/help/index_<locale>.html` exists, recursively copy `<installation dir>/help/*` over `helpDir` (REPLACE_EXISTING) – allows shipping customised/extra help with the installation.
5. Open: write `<java.io.tmpdir>/local_launcher.html` (UTF-8) containing
   `<meta http-equiv="refresh" content="0; url=<helpDir>/index_<locale>.html?redirectPage=<page>" />` and `<body onload="setTimeout(location.href='file://<same>', 1000)">` (Firefox blocks meta refresh to file URLs), then `Desktop.browse("file:///<tmp>/local_launcher.html")`. Back-slashes are converted to `/`.
6. On failure: error dialog `SimpleAfirma.58` ("No se ha podido cargar la ayuda correctamente.") with code `200004`.

`index_<locale>.html` is a frame page with a left sidebar (CSS colour `#96181c`) listing pages and a `<div id='dynamicContent'>` where `loadScreen(page)` injects `<object data="<locale>/<page>">`; on load it reads `?redirectPage=` and loads that page (sanitising `\`, `..`, spaces, `?&<>`).

Entry points: Help menu "Ayuda de Autofirma" (F1) and DNIe screen F1 → `Autofirma.html`; visible-PDF-signature dialog "Ayuda" button → `pgs/VentanaPdfVisible.html`. Certificate-selection dialog F1 opens the online help `https://github.com/ctt-gob-es/clienteafirma/wiki/Help-desktop-select-certs-<ll>-<CC>` (from `/resources/selectiondialogutil.properties`, key `helpUrl`).

Help pages per language (`<ll_CC>/`): `Autofirma.html` and `pgs/` `CambioIdioma.html`, `Licencia.html`, `LineaComandos.html`, `MenuPlugins.html`, `MenuPreferencias.html`, `MenuRestauracion.html`, `PantallaDetalle.html`, `PantallaEspera.html`, `PantallaFirma.html`, `Plugins.html`, `VentanaCertificadosConfianza.html`, `VentanaConfigurarProxy.html`, `VentanaListaBlancaDominios.html`, `VentanaPdfVisible.html`, plus `gfx/*.png` screenshots and `AutofirmaHelpIcon.png`; shared images in `shrd/`. A legacy `JavaHelp/` set (es only) is bundled but unused.

Gotcha: `fileslist.txt` is missing a newline (`va_ES/pgs/VentanaPdfVisible.htmleu_ES/Autofirma.html`), so `va_ES/pgs/VentanaPdfVisible.html` and `eu_ES/Autofirma.html` are never extracted. Rust port: embed the help tree and extract it completely (or serve it from memory).

### 1.16 macOS integration

- `OSXHandler`: reflection adapter that registers handlers on `com.apple.eawt.Application` (falling back to `java.awt.desktop.*Handler` interfaces): `setAboutHandler` (→ About dialog), `setPreferencesHandler` (→ Preferences dialog; on macOS the Preferences item is therefore *not* in the Tools menu), `setQuitHandler` (→ `askForClosing()`). Quirk: the quit handler never calls `QuitResponse.performQuit()/cancelQuit()`. There is no open-file / open-URI handler: URLs arrive via the native stub (1.1).
- Menus: no "Salir" and no "Acerca de" items (provided by the app menu); no mnemonics on macOS menu items (Apple HIG).
- Dock icon set from `logo_cliente_256.png`.
- `so/macos` helpers:
  - `AppleScript(script).run()`: `/usr/bin/osascript -e <script>`; non-zero exit → `IOException` (stderr logged); returns stdout (UTF-8).
  - `ShellScript(text|file, deleteAfter).run()/runAsAdministrator()`: `/usr/bin/osascript -e 'do shell script "<text or file path>"' [with administrator privileges]` (shows the macOS admin password prompt); optional deletion of the script file afterwards.
  - `MacUtils.newScriptFile()` (temp `afirma*.sh`), `writeScriptFile(sb, file, append)` (writes text + `\n`), `executeScriptFile(file, admin, delete)`; `closeMacService(id)` runs `kill -9 $(ps -ef | grep <id> | awk '{print $2}')` (legacy socket service); `focusApplication()` runs AppleScript `tell me to activate` (brings the Java app to front before showing protocol dialogs); `getMacApp(jar)` finds `Contents/MacOS/<jarname-without-.jar>` when the JAR is at `Contents/Resources/JAR/` (used to restart the app).
  - `UnixUtils.addAllPermissionsToFile(f)` (chmod 777), `addExexPermissionsToAllFilesOnDirectory(dir)` (777 on every child) – used by restore-config to make `certutil` and scripts executable (§10).

### 1.17 Restart helper (`DesktopUtil.getResetApplicationCommand`)

Used after changing the language (§11). Based on the code-source location: running from a directory → no restart possible (`null`); a `.jar` inside a macOS bundle → `[<bundle>/Contents/MacOS/Autofirma]`; other `.jar` → `[<java.home>/bin/java, -jar, <jar>]` (JVM options are lost); `.exe` → `[<exe>]`; otherwise `null` (the user is asked to restart manually).

### 1.18 Error-code catalogue (`SimpleErrorCode`)

Codes are `ErrorCode(code, internal description)`; shown to users together with localized messages and returned to web pages in protocol mode (mapping to `SAF_xx` legacy codes is in the protocol spec).

| Code | Constant | Meaning |
|---|---|---|
| 200004 | Internal.CANT_LOAD_HELP | Help could not be loaded |
| 200005 | Internal.NOT_VALID_PLUGIN | Invalid plugin |
| 200100 | Internal.ENCRIPTING_SIGNATURE | Error encrypting signature for intermediate server |
| 200101 | Internal.ENCRIPTING_SIGNING_CERT | Error encrypting signing certificate for intermediate server |
| 200116 | Internal.ENCRIPTING_SIGNATURE_EXTRA_DATA | Error encrypting extra signature info |
| 200117 | Internal.POSTPROCESING_SIGNATURE | Signature post-processing error |
| 200118 | Internal.UNKNOWN_SIGNING_BY_SOCKETS_ERROR | Unknown error signing via sockets |
| 200119 | Internal.LOAD_FILE_TO_VIEW | Error loading local file to view signature |
| 200200 | Internal.ENCRIPTING_SELECTED_CERT | Error encrypting selected certificate |
| 200201 | Internal.UNKNOWN_SELECTING_CERT_ERROR | Unknown error in certificate selection |
| 200301 | Internal.CANT_SAVE_FILE | Cannot save file |
| 200305 | Internal.UNKNOWN_SAVING_DATA_ERROR | Generic save error |
| 200400 | Internal.ENCRIPTING_BATCH_RESULT | Error encrypting batch result |
| 200401 | Internal.ENCRIPTING_BATCH_SIGNING_CERT | Error encrypting batch signing certificate |
| 200410 | Internal.INTERNAL_JSON_BATCH_ERROR | Internal JSON batch error |
| 200411 | Internal.INTERNAL_XML_BATCH_ERROR | Internal XML batch error |
| 200412 | Internal.INTERNAL_LOCAL_BATCH_ERROR | Internal local batch error |
| 200413 | Internal.UNKNOWN_BATCH_ERROR | Unknown batch error |
| 200600 | Internal.UNKNOWN_LOADING_DATA_ERROR | Generic load error |
| 200601 | Internal.CANT_LOAD_FILE | Cannot load local file |
| 200701 | Internal.NEEDS_UPDATED_VERSION | Application must be updated |
| 200702 | Internal.NO_DETECTED_PROXIES | No system proxies detected |
| 200800 | Internal.ERROR_LOAD_TRUSTED_CERT | Error loading trusted certificate |
| 200801 | Internal.TRUSTSTORE_INCORRECT_INSTALLATION | Autofirma SSL/trust store not correctly installed |
| 220001 | Internal.SOCKET_INITIALIZING_ERROR | Cannot open communication socket |
| 220002 | Internal.DECRYPTING_PARAMS_ERROR | Error decrypting server data |
| 220003 | Internal.ERROR_RECIVED_FROM_CLIENT | Client already reported an error |
| 220004 | Internal.ENCRYPTING_PARAMS_ERROR | Error encrypting server data |
| 220008 | Internal.LOADING_SSL_KEYSTORE_ERROR | Cannot load SSL keystore |
| 230100 | Internal.GENERIC_LANGUAGE_IMPORT_ERROR | Language import error |
| 230101 | Internal.CANT_READ_FILE | Cannot read language ZIP |
| 230102 | Internal.CANT_CREATE_DIRECTORY | Cannot create language directory |
| 400002 | Communication.PROXY_CONNECTION | Wrong proxy connection |
| 401100 | Communication.RECIVING_DATA_OF_SIGN_OPERATION | Error downloading sign operation |
| 401101 | Communication.RECIVING_DATA_OF_CERT_OPERATION | Error downloading cert-selection operation |
| 401102 | Communication.RECIVING_DATA_OF_BATCH_OPERATION | Error downloading batch operation |
| 401103 | Communication.RECIVING_DATA_OF_SAVE_OPERATION | Error downloading save operation |
| 401104 | Communication.RECIVING_DATA_OF_LOAD_OPERATION | Error downloading load operation |
| 401105 | Communication.RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION | Error downloading sign&save operation |
| 401106–401111 | Communication.RECIVING_DATA_OF_{SIGN,CERT,BATCH,SAVE,LOAD,SIGN_AND_SAVE}_TIMEOUT | Intermediate-server retrieval timeout (in that order) |
| 401200 | Communication.SENDING_RESULT_OPERATION | Error sending result |
| 401201 | Communication.SENDING_RESULT_TIMEOUT | Timeout calling intermediate storage service |
| 420001 | Communication.EXTERNAL_REQUEST | Request from an external port |
| 420501 | Communication.SENDING_RESULT_OPERATION_BY_SOCKET | Error sending result by socket |
| 420502 | Communication.READING_FROM_SOCKET | Cannot read socket data |
| 500005 | Functional.MINIMUM_VERSION_NON_SATISTIED | Web requested a newer Autofirma version (`mcv`) |
| 500006 | Functional.SIGNER_REQUIREMENT_NOT_SUPPORTED | Signer requested unsupported data |
| 500007 | Functional.VALIDATOR_REQUIREMENT_NOT_SUPPORTED | Validator requested unsupported data |
| 501001 | Functional.NO_CERTS_FOUND_SIGNING | No certificates found (sign) |
| 501009 | Functional.CANT_IDENTIFY_SIGNATURE_FORMAT | Cannot identify a signature format for the data |
| 501010 | Functional.VISIBLE_SIGNATURE_IS_MANDATORY | Visible PDF signature marked mandatory |
| 502001 | Functional.NO_CERTS_FOUND_SELECTING_CERT | No certificates found (select cert) |
| 504001 | Functional.NO_CERTS_FOUND_SIGNING_BATCH | No certificates found (batch) |
| 521000 | Functional.POLICY_DEFAULT_ERROR | Error configuring policy |
| 521001 | Functional.INVALID_POLICY_IDENTIFIER | Policy identifier null/empty |
| 521002 | Functional.INVALID_POLICY_IDENTIFIER_URI | Identifier must be a valid URI |
| 521003 | Functional.MISSING_DIGEST_ALGORITHM | Hash given without algorithm |
| 521004 | Functional.UNREACHABLE_POLICY_IDENTIFIER_URI | Without hash, identifier must be a reachable URI |
| 521005 | Functional.INVALID_POLICY_IDENTIFIER_HASH_BASE64 | Hash must be Base64 |
| 521006 | Functional.INVALID_POLICY_QUALIFIER_URI | Qualifier must be a valid URI |
| 521007 | Functional.INVALID_POLICY_IDENTIFIER_OID | Identifier must be a valid OID |
| 521008 | Functional.EMPTY_POLICY_HASH | Hash null/empty |
| 521009 | Functional.INVALID_POLICY_QUALIFIER_URL | Qualifier must be a valid URL |
| 521010 | Functional.INVALID_PROXY_CONFIG | Invalid proxy configuration |
| 530007 | Functional.INVALID_PLUGIN_FILE | Plugin not valid for import |
| 530009 | Functional.PLUGIN_FILE_NOT_FOUND | Plugin file not found |
| 600002 | Request.UNSUPPORTED_OPERATION | Operation not supported |
| 600121 | Request.INVALID_FORMAT_SIGNATURE_PARAM | Invalid signature property |
| 600420 | Request.INVALID_FORMAT_SIGN_BATCH_PARAM | Invalid batch property |
| 620009 | Request.UNSUPPORTED_REQUEST_SCHEME | Invocation URL scheme not supported |
| 620010 | Request.INVALID_SESSION_ID | Wrong websocket session id |
| 620011 | Request.UNSUPPORTED_PROTOCOL_VERSION | Unsupported browser protocol version |
| 620012 | Request.REQUEST_URI_NOT_FOUND | No invocation URI |
| 620013 | Request.PORTS_NOT_FOUND | No ports given |
| 620016 | Request.MALFORMED_REQUEST_TO_SOCKET | Wrong socket parameters |

Language-import errors use `LanguageManagementError.<code>` messages (`230000` generic "Ha ocurrido un error al importar el fichero de idioma", `230001` "No se ha podido leer correctamente el archivo ZIP", `230002` "Se ha producido un error al crear el directorio del idioma"). Quirk: `LanguageManager.addLanguage` throws code `230001` for every failure while the menu maps only `230101/230102` to specific messages, so users always see the generic `230000` text.

### 1.19 Reimplementation checklist for start-up

- Single binary with sub-command/URL classification identical to 1.3 (keep `-help`, keep exit codes 0 / −1→255).
- Protocol mode must not take the GUI lock; websocket mode must stay resident.
- Keep the `.lock` semantics (one desktop GUI per user) but prefer an OS-native single-instance mechanism that can also forward a file to the running instance (improvement).
- Honour `AUTOFIRMA_AVOID_UPDATE_CHECK`, `es.gob.afirma.doNotCheckUpdates` (accept as env var too), `AFIRMA_NSS_DISABLE_*` env vars.
- Load preferences → locale → theme → proxy → TLS/trust config (async) → mode dispatch, as above.
- On Linux set the window class/app-id so it matches the `.desktop` file. Quirk: Java sets `awtAppClassName="Autofirma"` while the deb `.desktop` declares `StartupWMClass=autofirma` (lower case).


## 2. GUI: main window, screens and flows

This section covers the desktop window of AutoFirma (`afirma-simple`, package `es.gob.afirma.standalone.ui` plus `SimpleAfirma`, `VisorFirma`, `DataAnalizerUtil`, `signdetails/**`, `crypto/**`). The PDF visible-signature dialogs, the certificate-selection dialog, keystore loading and the generic JSE dialogs (file choosers, password prompts, message boxes) are in §3. Preferences dialog: §4. Restore-config dialog: §10. Plugin-management dialog and plugin internals: §7. Startup, single instance, logging, look & feel and help: §1. Accessibility as a whole: §12.

All label texts below are the Spanish (`es_ES`) values from `properties/simpleafirmamessages/simpleafirmamessages_es_ES.properties`, given as `"texto"` (key `Key.N`). `%0`, `%1` are positional placeholders.

### 2.1 Overview and state machine of the main window

There is one main top-level window (`MainScreen`, a `JFrame`). Its content is a scroll pane (unit increment 30 px) whose viewport shows exactly one "current panel" at a time. `SimpleAfirma` owns the frame, the menu bar (`MainMenu`) and the reference `currentPanel`. Switching panels means: put the new panel in the viewport, `pack()`, then hide, disable and make non-focusable the previous panel.

Window properties:
- Initial size: the scroll pane preferred size is **780 × 580** (`DEFAULT_WINDOW_WIDTH/HEIGHT` in `SimpleAfirma`). The frame is packed and centred on screen.
- If screen height ≤ 600 px, the window starts maximised (`LookAndFeelManager.needMaximizeWindow()`).
- Close button: `DO_NOTHING_ON_CLOSE`. The window listener calls `askForClosing()` (see §2.12).
- Title: `"Autofirma v%0"` (`SimpleAfirma.10`, %0 = version). On the single-result screen the title becomes `"Autofirma vX - <signature file name>"`. On the multi-result screen it becomes `"Autofirma vX - <absolute output dir>"`.
- macOS: the root pane client property `Window.documentFile` is set to the signature file or output dir (title-bar proxy icon). It is reset to `null` on the sign screen.
- Window icons: `/resources/logo_cliente_{16,24,32,48,128,256,512}.png` (`DesktopUtil.getIconImages()`).

Panels (states):

| State | Panel class | Preferred size | Plugin window id |
|---|---|---|---|
| DNIE_WAIT | `DNIeWaitPanel` | 600×420 | – |
| SIGN (empty drop zone / loaded files) | `SignPanel` (+ `SignPanelFilePanel` or `SignPanelMultiFilePanel`) | 600×520 (minimum before scrollbars appear) | `INPUT_DATA` |
| RESULT_SINGLE | `SignDetailPanel` | 600×500 | `SINGLE_RESULT` |
| RESULT_MULTI | `SignResultListPanel` | 600×540 | `MULTI_RESULT` |
| VIEWER (separate window) | `VisorFirma` + `VisorPanel` | window 780×650, panel 600×540 | `VISOR` |

```
                     (app start, no args)            (CLI "sign -gui -i F", see §5;
                              |                        Windows "Firmar con Autofirma")
             hideDnieStartScreen==false                        |
             AND no preselected file                           |
             AND >=1 PC/SC reader present?                     |
                 /yes                \no                       |
                v                     v                        v
        +---------------+      +-----------------------------------------+
        |  DNIE_WAIT    |----->|  SIGN (empty drop zone)                 |
        | (no menu bar) | DNIe |  loadDefaultKeyStore(); menu bar shown  |
        +---------------+ / no +-----------------------------------------+
           F1 -> help      DNIe        | drop / "Seleccionar ficheros" / menu Abrir
                                       v
                       +---------------------------------+
                       | SIGN (1 file: SignPanelFilePanel|<----+ drop again /
                       |  or N files: MultiFilePanel)    |-----+ select again
                       +---------------------------------+
                                | "Firmar" (enabled when keystore ready)
                                v
           [confirm dialog?] -> [PDF visible-sig dialogs? §3] -> [cert dialog §3]
           -> [N>1: choose output dir] -> sign loop -> [N==1: save dialog]
                    | cancel anywhere: stay in SIGN (files kept)
                    v
      N==1 +------------------+          N>1 +--------------------+
           |  RESULT_SINGLE   |              |   RESULT_MULTI     |
           +------------------+              +--------------------+
                 | "Firmar más ficheros"            | "Firmar más ficheros"
                 +------------> new empty SIGN <----+

  Menu "Ver firma" (any state), "Ver fichero" on .csig/.xsig, double click on a
  result row  ---> VIEWER window (independent JFrame, or modal JDialog when a parent is given)
  CLI "verify -gui -i F" / Windows ".csig/.xsig -> Verify" ---> VIEWER standalone (exit on close)
```

Entry points into the GUI (detail of argument parsing in §1 and §5):
1. No arguments: `SimpleAfirma.initGUI(null, null)`. This shows DNIE_WAIT or SIGN.
2. `sign|cosign|countersign -gui -i <file> [...]` (CLI, `CommandLineLauncher.signByGui`): `initGUI(file, signConfig)`. The DNIe screen is never shown. The file is preloaded with an externally supplied `SignOperationConfig` (operation, optional signer, optional digest algorithm, see §2.4.3). Windows Explorer's "Firmar con Autofirma" registers `Autofirma.exe sign -gui -i "%1"` (§9).
3. `verify -gui -i <file>` runs `new VisorFirma(true, null).initialize(false, file)`. This is a standalone viewer: closing it calls `System.exit(0)`. Windows registers `verify -gui -i "%1"` for `.csig` and `.xsig`.

### 2.2 DNIe wait screen (`DNIeWaitPanel`)

When it is shown (`SimpleAfirma.initGUI`):
- no preselected file, AND
- preference `hideDnieStartScreen` is false, AND
- `javax.smartcardio.TerminalFactory.getDefault().terminals().list()` is non-empty. Any exception while listing readers means the screen is not shown.

While this screen is visible the menu bar is **not** installed. It is added only when the user leaves the screen.

Layout, top to bottom on a background of `SECUNDARY_COLOR` (white, or black in Windows high contrast):
1. Image `/resources/lectordnie.png`, scaled to fit while keeping aspect ratio (`ScalablePane`).
2. Text: `"Inserte su DNIe en el lector de tarjetas y pulse el botón "Continuar con DNIe""` (`DNIeWaitPanel.3`).
3. Text: `"Una vez insertado, no extraiga el DNIe ni el lector de tarjetas durante toda la ejecución de este programa"` (`DNIeWaitPanel.7`). Both texts are drawn by `ResizingTextPanel`, see §2.3.2.
4. Buttons:
   - `"Continuar con DNIe"` (`DNIeWaitPanel.4`), mnemonic C. Fires property `"DNI"`.
   - `"Usar almacén por defecto"` (`DNIeWaitPanel.0`), mnemonic u. Fires `"NoDNI"`. Accessible description `DNIeWaitPanel.1`, name `DNIeWaitPanel.2`.
5. Checkbox `"No volver a mostrar esta pantalla inicial y trabajar siempre con el almacén por defecto"` (`DNIeWaitPanel.8`). It starts with the value of `hideDnieStartScreen` and **writes the preference immediately** on every change.

Keyboard, active on the buttons and the checkbox:
- ESC is the same as "Usar almacén por defecto".
- F1 fires `"F1"` and opens the help (`SimpleAfirma.showHelp("Autofirma.html")`). F1 is ignored on macOS.

Transitions handled by `SimpleAfirma.propertyChange`:
- `"NoDNI"` runs `loadDefaultKeyStore()` then `loadMainApp()`, which goes to the SIGN screen and installs the menu bar.
- `"DNI"` sets a wait cursor, then runs `SimpleKeyStoreManagerWorker(dnie=true, forced = a keystore was already preloaded)` in the background (see §3). It then calls `loadMainApp()` immediately, without waiting for the worker. If the DNIe cannot be initialised it falls back to `loadDefaultKeyStore()`.
- `"F1"` opens the help.

Quirk: the accessible name and description of the DNIe button use a double lookup (`getString(getString("DNIeWaitPanel.5"))`). Screen readers therefore get the "missing key" marker `!…!`.

### 2.3 Sign screen (`SignPanel`)

`SignPanel` implements `LoadDataFileListener` (`loadFiles(File[], SignOperationConfig)`), `SignatureExecutor` (`initSignTask`, `relaunchTask`, `finishTask`) and `PluginButtonsContainer`. The layout is a vertical GridBag with three rows.

#### 2.3.1 Upper panel (welcome)
- Title `"Bienvenido a Autofirma"` (`SignPanel.14`), plain font at 26 pt, colour `new Color(3399)` = RGB(0,13,71) (dark navy). The colour is not applied in high contrast.
- Intro HTML text (`SignPanel.40`):
  > "En esta pantalla puede firmar electrónicamente ficheros que se encuentren en su disco duro. Cuando firma electrónicamente un fichero pueden incorporarse a este ciertos datos personales, entre los que pueden encontrarse su número de DNI, su nombre y apellidos o incluso información sobre su situación laboral si utiliza un certificado profesional. Consulte las políticas de seguridad y protección de datos de los receptores de los ficheros firmados antes de enviarlos o distribuirlos. A partir de este punto, si inserta o extrae una tarjeta inteligente o dispositivo criptográfico USB deberá seleccionar el almacén de claves apropiado desde el diálogo de selección de certificados o pulsar el botón Actualizar para recargar el almacén seleccionado."
- Button `"Seleccionar ficheros a firmar"` (`SignPanel.32`), mnemonic S, accessible description `SignPanel.33`, accessible name `SignPanel.34`. It gets the initial focus. It opens a file chooser (§3) titled `"Seleccione el fichero a firmar"` (`SignPanel.35`) with **multi-selection on**, no filter, files only. Then it calls `loadFiles(selected, null)`. Cancel does nothing.

#### 2.3.2 Lower panel (drop zone / file info + Sign button)
- A scroll pane with a 1 px line border (gray, or white in high contrast). On macOS both scrollbars are always visible. Elsewhere they appear as needed.
- Initial content: the drop zone, a `ResizingTextPanel` showing `"Pulse el botón o arrastre ficheros o directorios a esta área"` (`SignPanel.41`). Its tooltip and accessible description are `SignPanel.42`, accessible name `SignPanel.43`. Colours: dark gray background, light gray text. `ResizingTextPanel` draws the single line at x=30 px, vertically centred. On each paint it grows or shrinks the font in 1 pt steps until the text width plus 90 px just fits the panel width. On Linux it has a black 1 px border.
- Drag & drop (`DropDataFileListener`) is attached to the drop panel **and** to the scroll-pane viewport. The user can therefore drop again after files are loaded, which replaces the selection.
  - Only the OS file-list flavour is accepted; anything else is rejected.
  - Entries whose string form starts with `http://`, `https://` or `ftp://` are ignored with a log warning.
  - `file://` URIs are converted to local paths. Anything else is used as a path.
  - The resulting list goes to `loadFiles(files, null)`.
- Button `"Firmar"` (`SignPanel.45`), mnemonic F, horizontal margin 30 px. It is **disabled** until files are loaded **and** the keystore is ready. While files are loaded but the keystore is not ready, the button shows the animated `/resources/progress.gif` instead of text, with tooltip `"Por favor, espere mientras se inicializa el almacén de claves"` (`SignPanel.13`). When the keystore becomes ready (`SimpleAfirma.setKeyStoreManager` → `SignPanel.notifyStoreReady()`), the text comes back and the button takes the focus. If the keystore fails to load (`ksm == null`), the error `"No se ha podido inicializar el almacén de claves.\nNo podrá realizar firmas electrónicas."` (`SimpleAfirma.6`) is shown.

#### 2.3.3 Plugin buttons strip
Below the lower panel there is a horizontal separator and a left-aligned flow of plugin buttons for window `INPUT_DATA` (§2.13). The strip is hidden when there are no buttons.

#### 2.3.4 Loading files (`SignPanel.loadFiles`)
1. Wait cursor.
2. `filterFiles`: walk the given list breadth-first. A path that exists and is readable is either a regular file, which is added, or a directory, whose children are all appended to the work list. **Directories are expanded recursively**, with no depth limit, no hidden-file filter and no extension filter. Non-existent or unreadable entries are silently dropped.
3. If no file remains: error `"No se ha podido cargar el fichero seleccionado."` (`SignPanel.123`), title `"Error"` (`SimpleAfirma.7`).
4. For each file, build a `SignOperationConfig` (§2.4). The **whole file is read into memory**. A file that fails to read, including out-of-memory, is logged and skipped.
5. One config shows `SignPanelFilePanel`. More than one shows `SignPanelMultiFilePanel`. Exactly zero valid configs leaves the old view in place.
6. Update the Sign button (enabled if `isKeyStoreReady()`) and focus the lower panel.

The menu item "Abrir archivo a firmar" and `SimpleAfirma.loadFileToSign(file, cfg)` call the same code, but only while the current panel is a `SignPanel`. A read exception there gives `"No se ha podido leer el contenido del fichero a firmar, compruebe que no esta abierto por otra aplicación y si está en almacenamiento extraible pruebe a expulsarlo e insertarlo de nuevo"` (`SimpleAfirma.0`).

### 2.4 File analysis and signature-format auto-selection

#### 2.4.1 `SignOperationConfig` (per-file model)

| Field | Meaning | Default |
|---|---|---|
| `fileType` | `FileType` enum (below) | `BINARY` |
| `dataFile` | input file | – |
| `signatureFile` | output file, set after a successful save. `null` means the file failed | `null` |
| `cryptoOperation` | `SIGN`, `COSIGN`, `COUNTERSIGN_LEAFS`, `COUNTERSIGN_TREE` | `SIGN` |
| `signer` | signer implementation (format) | – |
| `extraParams` | `Properties` passed to the signer | – |
| `signatureFormatName` | display name (table in 2.4.4) | – |
| `signValidity` | `List<SignValidity>` when the input is already a signature, else `null` | `null` |
| `invalidSignatureText` | text shown when validity is KO/UNKNOWN/PENDING | `null` |
| `digestAlgorithm` | overrides the `signatureHashAlgorithm` preference | `null` |

`clone()` copies everything, gives `extraParams` its own copy, and makes `signValidity` an unmodifiable list.

#### 2.4.2 Detection rules (`DataAnalizerUtil` + `SignPanel.configureDataSigner`)

Detection primitives. They are byte-content based; **file extensions are never used**:

| Test | Rule |
|---|---|
| `isPDF` | length ≥ 70 bytes, starts with ASCII `%PDF-`, and a PDF parser can open it. A password-protected PDF counts as PDF. |
| `isFacturae` | XML parses (secure parser), the root local name is `Facturae`, and its direct children include local names `FileHeader`, `Parties` and `Invoices`. A signed invoice still matches. |
| `isOOXML` | ZIP (magic) with entries `[Content_Types].xml`, `_rels/.rels`, `docProps/app.xml` and `docProps/core.xml`. Backslash variants of the last three are accepted. |
| `isODF` | ZIP whose `mimetype` entry is one of `application/vnd.oasis.opendocument.text`, `…spreadsheet` or `…presentation`. |
| `isXML` | a SAX parse with a secure parser succeeds. |
| `isSignedPDF/ODF/OOXML/XML/Binary/Facturae` | the corresponding signer's `isSign`. Signed XML means XAdES or XMLDSig. Signed binary means CMS or CAdES. |

`AOSignerFactory.getSigner(data)` (signature sniffing) tries, in this order, the formats that allow autodetection: CAdES, CAdES-ASiC-S, CMS/PKCS#7, FacturaE, XAdES, XAdES-ASiC-S, XMLDSig, PAdES, ODF, OOXML. The first `isSign == true` wins.

Default flow when no external config is given (`configureDataSigner(config, data)`). The first matching branch wins:

1. **PDF**: `fileType=PDF`, signer = format named by preference `defaultSignatureFormatPdf` (default `PAdES`). If the signer is the PAdES signer and the PDF already contains signatures, `cryptoOperation=COSIGN`. This disables the stamp and certified-signature options and hides "(Cambiar)".
2. **FacturaE**: `fileType=FACTURAE`, signer from `defaultSignatureFormatFacturae` (default `FacturaE`).
3. **OOXML**: `fileType=OOXML`, signer from `defaultSignatureFormatOoxml` (default `CAdES`).
4. **ODF**: `fileType=ODF`, signer from `defaultSignatureFormatOdf` (default `CAdES`).
5. Otherwise, sniff the signature with `AOSignerFactory.getSigner(data)`:
   - if a signer is found: XAdES signer gives `fileType=SIGN_XADES`, **any other signer** gives `SIGN_CADES`. In both cases `cryptoOperation=COSIGN`. Quirk: XMLDSig, CMS and ASiC-S inputs are labelled `SIGN_CADES`.
   - else if `isXML`: `fileType=XML`, signer from `defaultSignatureFormatXml` (default `XAdES`).
   - else: `fileType=BINARY`, signer from `defaultSignatureFormatBin` (default `CAdES`).
6. If `signer.isSign(data)` (the input is already a signature for the chosen signer), run **pre-validation** (2.4.5).
7. `signatureFormatName = getSignatureName(signer)`.
8. `extraParams = ExtraParamsHelper.loadExtraParamsForSigner(signer)` (2.4.6), plus `confirmDifferentProfile=true` (XAdES extra param `CONFIRM_DIFFERENT_PROFILE`).

The preference values are format names resolved by `AOSignerFactory.getSigner(String)`, case-insensitive. The accepted names include `CAdES`, `CAdES-ASiC-S`, `CMS/PKCS#7`, `FacturaE`, `Factura-e`, `XAdES`, `XAdES Detached`, `XAdES Enveloped`, `XAdES Enveloping`, `XAdES-ASiC-S`, `XMLDSig*`, `Adobe PDF`, `PAdES`, `ODF (Open Document Format)`, `ODF`, `OOXML (Office Open XML)`, `OOXML`. The full key list is in §4.

Flow with an externally supplied config (`configureDataSigner(newCfg, cfg, data)`, used by `sign -gui`):
1. Same type order: PDF, FacturaE, OOXML, ODF, then **XML before anything else**, then BINARY. There is no signature sniffing step.
2. signer = `cfg.signer` if set, else the per-type default format.
3. If `signer.isSign(data, cfg.extraParams)`: re-label `SIGN_CADES` for the CAdES signer or `SIGN_XADES` for the XAdES signer, then pre-validate.
4. `cryptoOperation` and `digestAlgorithm` are copied from `cfg`.
5. **Gotcha:** `extraParams` ends up containing only `confirmDifferentProfile=true`. Neither the preference-derived parameters (2.4.6) nor the `-config` extra params from the command line are applied in this path. They are applied only if the user then uses "(Cambiar)". A reimplementation should probably merge preference params with CLI params.

#### 2.4.3 `FileType` enum (icon, tooltip, description)

| FileType | Large icon (`/resources/…`) | Tooltip | Description ("Tipo de fichero: …") |
|---|---|---|---|
| PDF | `icon_pdf_large.png` | `SignPanel.0` "Fichero de tipo Portable Document Format (PDF)" | `SignPanel.9` "Documento Adobe PDF" |
| BINARY | `icon_binary_large.png` | `SignPanel.12` "Fichero binario genérico" | `SignPanel.11` "Documento binario genérico" |
| XML | `icon_xml_large.png` | `SignPanel.8` "Fichero de tipo XML" | `SignPanel.10` "Documento XML" |
| FACTURAE | `icon_facturae_large.png` | `SignPanel.17` "Fichero de tipo Factura-e (Factura Electrónica)" | `SignPanel.20` "Factura-e (Factura Electrónica)" |
| SIGN_CADES | `icon_sign_large.png` | `SignPanel.6` + " (CAdES)" | `SignPanel.39` "Documento de firma" + " (CAdES)" |
| SIGN_XADES | `icon_sign_large.png` | `SignPanel.6` + " (XAdES)" | `SignPanel.39` + " (XAdES)" |
| OOXML | `icon_office_win_large.png` | `SignPanel.38` "Fichero OOXML (Office Open XML)" | `SignPanel.37` "Documento Microsoft Office (OOXML)" |
| ODF | `icon_openoffice_large.png` | `SignPanel.32` (quirk: the text is "Seleccionar ficheros a firmar"; it should be `SignPanel.30`) | `SignPanel.31` "Fichero ODF (Open Document Format)" |

Icons are drawn with `ScalablePane`, which scales the image to fit while keeping the aspect ratio, on a transparent background. The minimum size on the single-file panel is 128×128. In lists they are rendered at 32×32.

#### 2.4.4 Display format names (`SignPanel.getSignatureName`)
Mapped by signer class (`instanceof`, first match): `AOPDFSigner` → `"Firma PDF"` (`SignPanel.104`); `AOFacturaESigner` → `"Firma de FacturaE"` (`.105`); `AOXAdESSigner` → `"Firma XAdES"` (`.106`); `AOCAdESSigner` → `"Firma CAdES"` (`.107`); `AOODFSigner` → `"Firma ODF"` (`.108`); `AOOOXMLSigner` → `"Firma OOXML"` (`.109`). Any other signer → `"Formato desconocido"` (`.110`). Plugins receive this localized string as the "signature format" (§2.13).

#### 2.4.5 Pre-validation of inputs that are already signatures (`SignPanel.setValidationInfo`)
- Validator chosen by signer: CAdES signer → binary validator; XAdES or FacturaE → XML validator; PAdES → PDF validator. Any other signer (ODF, OOXML, CMS…) is not validated and `signValidity` stays `null`.
- Validation params:
  - `checkCertificates=true`
  - `pagesToCheckShadowAttack=all`
  - `allowShadowAttack=true` **when preference `allowShadowAttack` is false** (the default). The preference name is inverted: its value `true` means "check for PDF shadow attacks", see §4.
- Outcome:
  - Result list `validityList` (the first element is the overall status).
  - If the first status is KO or UNKNOWN, `invalidSignatureText = buildErrorText(type, error)`.
  - A `RuntimeConfigNeededException` during validation gives `[PENDING_CONFIRM_BY_USER, SUSPECTED_SIGNATURE, exception]`, with text = the exception message.
  - Any other exception gives `[KO, CORRUPTED_SIGN]`.
- `buildErrorText`: prefix `"Firma inválida"` (`SignPanel.140`) for KO, or `"No se puede completar la validación"` (`SignPanel.141`) for UNKNOWN, then `": "` and the error text:

| VALIDITY_ERROR | key | text |
|---|---|---|
| NO_DATA | SignPanel.125 | No se encuentran los datos firmados |
| CORRUPTED_SIGN | .126 | Información corrupta |
| NO_MATCH_DATA | .127 | La firma no se corresponde con los datos firmados |
| NO_SIGN | .128 | No se encuentra la firma dentro del documento |
| CERTIFICATE_PROBLEM | .129 | No se puede extraer un certificado o no es válido |
| CERTIFICATE_EXPIRED | .130 | Certificado de firma caducado |
| CERTIFICATE_NOT_VALID_YET | .131 | Certificado de firma que aún no es válido |
| ALGORITHM_NOT_SUPPORTED | .132 | Algoritmo no reconocido o no soportado |
| CA_NOT_SUPPORTED | .133 | No se soporta la CA de expedición |
| CRL_PROBLEM | .134 | CRLs de firma erróneas |
| PDF_UNKOWN_VALIDITY | .135 | No se puede comprobar la validez de la firma PDF |
| OOXML_UNKOWN_VALIDITY | .136 | … OOXML |
| ODF_UNKOWN_VALIDITY | .137 | … ODF |
| UNKOWN_ERROR | .138 | No se puede comprobar la validez de la firma |
| UNKOWN_SIGNATURE_FORMAT | .139 | Formato de firma no reconocido |
| MODIFIED_DOCUMENT | .151 (no prefix) | Es posible que el documento se haya modificado despues de firmarse |
| OVERLAPPING_SIGNATURE | .152 (no prefix) | Posible solapamiento entre firmas visibles |
| CERTIFIED_SIGN_REVISION | .159 | El documento certificado no permitía nuevas firmas |
| other | – | prefix only |

#### 2.4.6 Preference → signer extra params (`ExtraParamsHelper.loadExtraParamsForSigner`)
The branch is chosen by signer class: FacturaE first, then XAdES, then PAdES, else CAdES. **The CAdES branch is also used for ODF, OOXML and CMS signers.** For every optional value: if the preference value is null or blank after trim, the param is not set.

- **FacturaE**:
  - `policyIdentifier` ← `facturaePolicyIdentifier`. Only when it is set are the next two read: `policyIdentifierHash` ← `facturaePolicyIdentifierHash`, `policyIdentifierHashAlgorithm` ← `facturaePolicyIdentifierHashAlgorithm`. Quirk: `facturaePolicyQualifier` is ignored.
  - `signatureProductionCity/Province/PostalCode/Country` ← `facturaeSignatureProduction{City,Province,PostalCode,Country}`.
  - `signerClaimedRoles` ← `facturaeSignerRole`.
- **XAdES**:
  - `ignoreStyleSheets=false` (always).
  - policy from `xadesPolicyIdentifier`, plus `…Hash`, `…HashAlgorithm` and `xadesPolicyQualifier` → `policyQualifier`.
  - `signerClaimedRoles` ← `xadesSignerClaimedRole`.
  - `signatureProduction*` ← `xadesSignatureProduction*`.
  - `format` ← `xadesSignFormat` (default `XAdES Detached`).
- **PAdES**:
  - policy from `padesPolicyIdentifier`, plus `…Hash`, `…HashAlgorithm` and `padesPolicyQualifier`.
  - `signReason` ← `padesSignReason`.
  - `signatureProductionCity` ← `padesSignProductionCity`.
  - `signerContact` ← `padesSignerContact`.
  - `signatureSubFilter` ← `padesBasicFormat`.
  - `obfuscateCertText` ← `Boolean.parseBoolean(padesObfuscateCertInfo)`, always set.
- **CAdES (and others)**:
  - policy from `cadesPolicyIdentifier`, plus `…Hash`, `…HashAlgorithm` and `cadesPolicyQualifier`.
  - `mode` = `implicit` if `cadesImplicitMode` is true, else `explicit`, always set.

#### 2.4.7 Changing the format ("(Cambiar)" → `ChangeFormatPanel`)
The "(Cambiar)" link exists only when `cryptoOperation == SIGN`. It opens an OK/Cancel plain dialog titled `"Configuración de firma"` (`ChangeFormatDialog.0`) with the label `"Seleccione el formato de firma que se utilizará para el fichero:"` (`ChangeFormatDialog.1`) and a combo box. Options by file type:

| FileType | Options (in order) | "Recommended" marker taken from |
|---|---|---|
| PDF | PAdES, CAdES, XAdES | `defaultSignatureFormatPdf` |
| OOXML | OOXML (Office Open XML), CAdES, XAdES | `defaultSignatureFormatOoxml` |
| FACTURAE | FacturaE, XAdES, CAdES | `defaultSignatureFormatFacturae` |
| XML, SIGN_XADES | XAdES, CAdES | `defaultSignatureFormatXml` |
| BINARY, SIGN_CADES | CAdES, XAdES | `defaultSignatureFormatBin` |
| ODF | ODF (Open Document Format), CAdES, XAdES | `defaultSignatureFormatOdf` |

- The recommended option is the one equal to the **built-in default value** of that preference (source DEFAULT, not the user value). It is shown with the suffix `" (Recomendado)"` (`ChangeFormatDialog.2`).
- Initial selection: the last option whose name is a substring of the current `signatureFormatName`. If none matches, the combo stays at index 0.
- On OK, the panel is rebuilt with the new signer: `signer = getSigner(selected name)`, `extraParams = loadExtraParamsForSigner(signer)` (this drops `confirmDifferentProfile`), and `signatureFormatName` is recomputed.

#### 2.4.8 Multi-sign operation for existing signatures
The sign panel has **no control** to choose co-sign vs counter-sign. When the user presses Sign (`setMultisignOpFromPreferences`), every config with `fileType` `SIGN_CADES` gets its operation from preference `cadesMultisign`, and every config with `SIGN_XADES` gets it from `xadesMultisign`. Values: `cosign` → COSIGN, `countersignLeafs` → COUNTERSIGN_LEAFS, anything else → COUNTERSIGN_TREE. Defaults are `cosign`. This overrides any operation given by the CLI `-gui` path. The labels `"Cofirma"`/`"Contrafirma (únicamente de los nodos hoja)"`/`"Contrafirma (de todo el árbol)"` (`SignPanel.116–118`) belong to the preferences UI (§4). The "Opciones Avanzadas" button (2.5) opens Preferences at the CAdES tab (index 2) or the XAdES tab (index 3) so the user can change this setting.

### 2.5 Single-file panel (`SignPanelFilePanel`)

White background (no colour in high contrast). It is a three-column GridBag.

1. **Left**: the large FileType icon (min 128×128).
2. **Centre (details)**:
   - Absolute path of the file in bold, font +3 pt.
   - Bold `"Información del documento:"` (`SignPanel.145`), then `DocumentInfoPanel`:
     - `"Tipo de fichero: %0"` (`SignPanel.46`), with the FileType description.
     - `"Fecha última modificación: %0"` (`SignPanel.47`), with the locale date-time format LONG date + SHORT time.
     - `"Tamaño: "` (`SignPanel.49`) + `floor(bytes/1024)` with locale grouping + `" KB"`. If the result is 0 it shows `"<1 KB"`.
   - Only if the file is a signature (`signValidity != null`): bold `"Resultado de validación:"` (`SignPanel.155`), then `ValidationInfoPanel`:
     - If `invalidSignatureText` is set: that text in **red** with icon `unknown_icon.png` (for UNKNOWN or PENDING_CONFIRM_BY_USER) or `ko_icon.png` (for KO).
     - Else if the status is OK: `"Firma válida"` (`SignPanel.156`) with `ok_icon.png`.
     - Then the link `"Detalles de la firma"` (`SignResultPanel.38`). It opens the `ValidationInfoDialog` (§2.9) for the file bytes.
   - Bold `"Configuración de firma:"` (`SignPanel.142`), then `SignatureConfigInfoPanel`:
     - Row: `"Formato: %0"` (`SignPanel.103`) + link `"(Cambiar)"` (`SignPanel.157`, only for operation SIGN).
     - If the extra params contain `policyIdentifier`, `signerClaimedRoles` or any `signatureProduction{StreetAddress,City,Province,PostalCode,Country}`: label `"Atributos de firma:"` (`SignPanel.143`) followed by bullet lines:
       - `" - Política de firma de la AGE 1.8"` (`PreferencesPanel.25`) or `"… AGE 1.9"` (`PreferencesPanel.73`), detected with `AgePolicy.isAGEPolicy18/19`. Otherwise `" - Política de firma a medida"` (`PreferencesPanel.26`).
       - `" - Lugar de firma"` (`SignPanel.149`) if any place field is set.
       - `" - Roles del firmante: %0"` (`SignPanel.144`).
       - Link `" - Ver todos los atributos..."` (`SignPanel.146`), which opens `SignatureAttributesDialog` (§2.10).
     - Options panel:
       - **PDF signer only**:
         - Checkbox `"Hacer la firma visible dentro del PDF"` (`SignPanel.44`), initial value = preference `padesVisibleSignature`.
         - Checkbox `"Insertar una marca visible dentro del PDF"` (`SignPanel.120`), initial value = `padesVisibleStamp`. When operation is COSIGN (the PDF is already signed) it is unchecked and disabled, followed by the label `"No se pueden aplicar marcas visibles a documentos ya firmados"` (`SignPanel.121`).
         - Only if preference `allowCertifiedPDF` is true: checkbox `"Generar firma PDF certificado"` (`PreferencesPanel.210`) and a combo with values `1` `"Certificada de autor"` (`PreferencesPanel.207`), `2` `"Certificada de autor para formularios"` (`.208`), `3` `"Certificada común"` (`.209`). The initial value comes from `padesCertificationLevel`: `0` means unchecked with the combo disabled; otherwise checked with the matching entry selected (index 0 if no match). The combo is enabled only while the checkbox is checked. If the PDF is already signed, both are disabled and the label `"No se pueden agregar firmas certificadas a un documento ya firmado"` (`SignPanel.158`) is added.
       - **SIGN_CADES or SIGN_XADES**: button `"Opciones Avanzadas"` (`SignPanel.119`), mnemonic a. It opens `PreferencesDialog.show(null, modal=true, tab)` with tab 2 (CAdES) for SIGN_CADES or 3 (XAdES) for SIGN_XADES. Tab order: 0 General, 1 PAdES, 2 CAdES, 3 XAdES, 4 Factura Electrónica, 5 Almacenes de claves.
3. **Right**: button `"Ver Fichero"` (`SignPanel.51`), mnemonic c, accessible name `"Botón de ver fichero"` (`SignPanel.52`).
   - Hidden if the extension (text after the last dot) is executable (see the list in §2.14, "Executable extensions") or is `LNK`.
   - Action: if the name ends with `.csig` or `.xsig`, open the signature viewer (`VisorFirma(false, null)`). Otherwise open the file with the OS default application (`Desktop.open`).
   - On failure: `"No se ha podido abrir el fichero.\nCompruebe que dispone de una aplicación instalada para ver este tipo de ficheros\ny que este no ha sido manipulado mientras se ejecutaba esta aplicación"` (`SignPanel.53`).

Hyperlink-styled labels ("(Cambiar)", "Ver todos los atributos…") are blue, or yellow in high contrast, and underlined. They are focusable and show a dashed 1 px border when focused. A mouse click or **Enter/Space** on key release activates them, and the hand cursor appears on hover.

### 2.6 Multi-file panel (`SignPanelMultiFilePanel`)
- Header row (bottom border black, white in high contrast; background `DEFAULT_COLOR` except on macOS and in high contrast): `"Fichero"` (`SignDataPanel.43`), `"Formato"` (`.44`, 120 px), `"Tamaño"` (`.45`, 60 px).
- A list with one row per config:
  - 32×32 type icon.
  - Path relative to the **shortest parent directory** among all files. The prefix is cut at that length + 1.
  - Format name.
  - Size: `0 KB` if 0; `1 KB` if < 1024; `N KB` if < 1,024,000 bytes; otherwise `N MB`. Quirk: the MB value uses integer division, so there are no decimals.
- Invalid inputs: the path is shown in **red** with the suffix `" (Firma inválida)"` (`SignPanel.147`). For PENDING_CONFIRM_BY_USER the suffix is instead `" (Validez a confirmar por el usuario)"`, from `SignValidity.validityTypeToString()`.
- Focused row: gray dashed border. The background is white unless in high contrast.
- Double-click (left button) or **Enter** on the selected row: inputs with validity info (signatures) open in the viewer; other files open with the OS default application.
- Right-click opens a context menu: `"Ver Fichero"` (bold, same action as double-click) and `"Ver atributos de firma"` (`SignPanel.148`, opens `SignatureAttributesDialog`).
- There are **no per-file options** in multi mode. The visible PDF signature is taken from preference `padesVisibleSignature`, the stamp is always false, and the certification level comes from preferences (see the quirk in 2.7 step 5).
- Accessible description: `"Lista de archivos a firmar "` + for each file `"Fichero<name>Formato<fmt>Tamaño<KB>KB"`.

### 2.7 Sign flow (`SignPanel.sign` → `SignPanelSignTask`)

Triggered by the "Firmar" button (or `SimpleAfirma.signLoadedFile()`):

1. **Invalid single signature guard**: if exactly one file is loaded, its first validity is KO, and preference `allowInvalidSignatures` is false: error `"No se permite agregar nuevas firmas a documentos con firmas no válidas."` (`SimpleAfirma.9`). Stop.
2. Create (but do not show yet) the modal wait dialog `CommonWaitDialog`:
   - title `"Proceso de firma electrónica"` (`SignPanel.50`)
   - message `"<html>Realizando la firma electrónica...<br>Esta tarea puede tardar varios minutos.</html>"` (`SignPanel.48`)
   - an indeterminate progress bar (circular style on macOS)
   - the close button does nothing; the dialog is centred and not resizable.
3. **Confirmation** (only if preference `confirmToSign` is true; default true): `ConfirmSignatureDialog`, title `"Autorizar firma"` (`ConfirmSignatureDialog.0`):
   - `"Se va a realizar la firma electrónica de un documento."` (`.1`) or `"Se va a realizar la firma electrónica de %0 documentos."` (`.2`)
   - `"Pulse "Aceptar" para dar fe de entender las implicaciones legales de firmar y autorizar la firma de los documentos seleccionados. En caso contrario, pulse "Cancelar"."` (`.4`)
   - checkbox `"Omitir esta confirmación en futuras operaciones de firma."` (`.5`)
   - buttons `"Aceptar"`/`"Cancelar"` (`.6`/`.7`).

   Cancel or closing the dialog aborts silently. Aceptar with the checkbox ticked stores `confirmToSign=false` and flushes it.
4. Apply the multi-sign operation from preferences (2.4.8).
5. **If any config uses the PDF signer**:
   - The wait dialog message becomes `"<html>Creando previsualización del PDF.<br>Esta tarea puede tardar varios minutos.</html>"` (`SignPanelSignTask.0`).
   - visible/stamp/certification come from the single-file panel controls if one file is shown. Otherwise: visible = `padesVisibleSignature`, stamp = false, and certification level = `padesCertificationLevel` if `padesVisibleSignature` is true. Quirk: the code reads `padesVisibleSignature` where `allowCertifiedPDF` was intended.
   - If the certification level is set and ≠ `0`, extra param `certificationLevel=<1|2|3>` is added to **all** configs.
   - Then configs are cloned and `VisiblePdfSignatureManager.getVisibleSignatureParams(clones, this, visible, stamp, frame)` runs (§3). It uses the first PDF. If the PDF has empty signature fields, the user picks one (`signatureField`), or picks none and gets the visible-signature editor if visible/stamp was requested. Otherwise, if visible/stamp was requested, it shows the visible signature/stamp editor. Otherwise it starts signing directly. The manager itself calls `initSignTask(configs)` when done.
   - Cancel disposes the wait dialog and keeps the panel. Any other exception is logged and signing proceeds **invisibly** with the clones.
6. Otherwise `initSignTask(configs)`.

`initSignTask`: wait cursor, start a background `SignPanelSignTask`, then show the modal wait dialog unless the task already finished. `finishTask()` (called from the task's `done()`) disposes the dialog and restores the cursor. `relaunchTask(pke, configs)` reruns the task with the already selected key (no new certificate prompt).

**Background task `doSignature()`**, in order:

a. **Certificate selection** (skipped on relaunch). Certificate filters are built from preferences, and when more than one applies they are AND-combined in a `MultipleCertificateFilter`:
   - `useOnlySignatureCertificates` adds the key-usage signing filter.
   - `skipAuthCertDnie` adds the "skip DNIe authentication cert" filter.
   - `useOnlyAliasCertificates` adds the pseudonym-only filter.

   The certificate dialog (§3, `AOKeyStoreDialog`) is called with check private keys = true, show expired = preference `showExpiredCerts`, check validity = true, the filters, and mandatory = false. Outcomes:
   - Cancel aborts silently.
   - No usable certificate: `"El almacén no contiene ningún certificado que se pueda usar para firmar."` (`SignPanel.29`).
   - Any other error: `"Se encontró un error durante la operación con el certificado seleccionado."` (`SignPanel.56`).

   The key is fetched from the keystore actually chosen in the dialog; the user may switch keystores there.
b. **Output directory** (only if more than one file): directory chooser titled `"Seleccione el directorio de salida"` (`SignPanelSignTask.3`), starting in the first file's parent. Cancel aborts.
c. `inputBasePath` = the shortest absolute parent path among the inputs.
d. **For each config**:
   1. If the input is a KO signature and `allowInvalidSignatures` is false, skip it. In multi mode it then shows as failed.
   2. Add **all JVM system properties** to the extra params. This lets `-Dkey=value` override signer parameters. A reimplementation may expose an equivalent "extra params from environment" or drop it.
   3. Multi mode: add `headless=true`, which forbids signer dialogs.
   4. Single mode with pre-validation status PENDING_CONFIRM_BY_USER caused by a `RuntimeConfigNeededException`:
      - CONFIRM: show a Yes/No question titled `"Confirmación requerida"` (`SignPanel.153`), whose text is the localized message for the exception's requestor code. Yes sets the param to `true` (or runs the exception's custom preparation). No aborts.
      - PASSWORD: show a password prompt. A password sets the param and marks relaunch. Cancel aborts.
      - Other request types: error `"No se pudo completar la firma: %0"` (`SignPanel.154`).
   5. Read the file into memory. On failure in single mode: `SignPanel.123`, abort. In multi mode: skip.
   6. Plugin pre-sign hook (2.13): the data may be replaced.
   7. Digest = `config.digestAlgorithm` if set, else preference `signatureHashAlgorithm` (default `SHA256`). The signature algorithm is `<digest>with<KeyAlg>` (e.g. `SHA256withRSA`, `SHA256withECDSA`), built from the private key algorithm. Failure shows an error. Quirk: it uses key `SignPanel.123` where `SignPanel.124` "Tipo de certificado no soportado: %0" was intended.
   8. Execute the operation: SIGN → `sign`; COSIGN → `cosign(data, …)`; COUNTERSIGN_LEAFS / COUNTERSIGN_TREE → `countersign(data, alg, LEAFS|TREE, targets=null, …)`.
      - Visible-PDF auto-recovery: if the signer reports that the requested page does not exist (`IncorrectPageException`), it removes `signaturePage`/`signaturePages` and retries. If the position is out of range (`InvalidSignaturePositionException`), it also removes the four `signaturePositionOnPage{LowerLeftX,LowerLeftY,UpperRightX,UpperRightY}` params and retries. In both cases the file name is recorded for a final warning.
   9. Error handling, single mode (multi mode skips to the next file unless stated):
      - User cancel (`AOCancelledOperationException`): abort silently.
      - Smart-card operation cancelled (`AOCancelledSMOperationException`): refresh the keystore and abort.
      - **Wrong PIN** (`PinException`): refresh the keystore, then reopen the certificate dialog **mandatorily filtered to the same certificate** (by its Base64 encoding), then restart the whole `doSignature`.
      - Keystore/key locked (`LockedKeyStoreException`): refresh the keystore and show `SignPanel.161`. Authentication error: show `SignPanel.162`. Quirk: neither key exists in the bundles, so the user sees `!SignPanel.161!` / `!SignPanel.162!`. Both abort even in multi mode.
      - `RuntimeConfigNeededException`: single mode prompts as in step d.4. On YES/password it sets the param and the relaunch flag, then returns; `done()` then calls `relaunchTask`. On NO it aborts silently. Multi mode: skip.
      - Format not applicable (`AOFormatFileException`): `"No se pudo completar la firma: %0"`.
      - Any other `Exception`/`Error`: `"Ocurrió un problema durante el proceso de firma, pruebe a reintentar\nla firma reiniciando la aplicación"` (`SignPanel.65`).
      - Out of memory: `"El fichero es demasiado grande y no se puede firmar por falta de memoria"` (`SignPanel.1`).
   10. Plugin post-sign hook (2.13): the signature may be replaced.
   11. Multi mode: save to `outDir/<relativeDir>/<signedName>`, where `relativeDir` = the input's parent path minus `inputBasePath` (keeps the sub-folder structure) and `signedName` = `signer.getSignedName(inputName, "_signed")` (table below). If preference `massiveOverride` is false and the file exists, try `name(1).ext`, `name(2).ext`, … with the counter inserted before the **last** dot. Missing directories are created. A save error marks the file as failed. On success `signatureFile` is set.
e. Call `reset()` on every loaded plugin.
f. **Single mode**: save dialog (generic JSE save dialog, §3):
   - title `"Guardar fichero firmado"` (`SignPanel.81`)
   - start directory = the input file's directory
   - proposed name = `getSignedName(name, "_signed")`
   - one format filter, preselected, plus "all files":

| Signer | Filter (desc key) | Proposed output name for input `doc.ext` |
|---|---|---|
| PAdES | `pdf` (`SignPanel.72` "Documentos Adobe PDF (*.pdf)") | `doc_signed.pdf` (a non-`.pdf` name gets `_signed.pdf` appended) |
| XAdES / FacturaE | `xsig`,`xml` (`SignPanel.76`) | `doc.ext_signed.xsig` |
| OOXML | `docx`/`pptx`/`xlsx`/`ooxml` (`SignPanel.91–94`) | `doc_signed.docx` / `.xlsx` / `.pptx` / `.ppsx`; others `doc.ext_signed.ooxml` |
| ODF | `odt`/`odp`/`ods`/`odf` (`SignPanel.96–99`) | `doc_signed.odt` / `.odp` / `.ods`; others `doc.ext_signed.odf` |
| CAdES, CMS and others | `csig`,`p7s` (`SignPanel.80`) | `doc.ext_signed.csig` (ASiC-S signers: `.asics`) |

   Save dialog behaviour:
   - If a specific filter is chosen and the name lacks a matching extension, the filter's first extension is appended.
   - If the file exists, a Yes/No/Cancel question titled `"Guardar como"` asks `"El fichero '%0' ya existe,\r\n¿desea sobrescribirlo?"`. No re-shows the chooser. Cancel aborts, and in that case the signature is discarded and the screen stays on SIGN.
   - A write error shows an error and re-shows the chooser.
   - Any other save failure: `SignPanel.88` "No se ha podido guardar el resultado de la firma…".
   - Success goes to `showResultsInfo(signature, config, signingCert)` (2.8).
g. **Multi mode**: go to `showResultsInfo(configs, outDir, signingCert)` (2.8.3).
h. If some files had invalid visible-signature pages or positions: warning titled `"Advertencia"` with `"No se pudo aplicar la firma visible correctamente a los siguientes documentos, \nya que la posición o páginas donde introducir la misma se encontraba fuera de rango:\n"` (`SignResultPanel.34`) followed by one file name per line.

Quirk: in step d.4, the PASSWORD branch sets the relaunch flag but then continues signing in the same pass. If that pass succeeds, the task signs (and asks to save) a second time.

PDF-specific confirmation prompts. Each is a `RuntimeConfigNeededException` requestor code with its message key, all Yes/No unless marked as a password prompt:
- `signingCertifiedPdf` → `allowSigningCertifiedPdfs`: "El PDF que desea firmar está certificado y no admite nuevas firmas. Agregar nuevas firmas invalidará la firma anterior.\n¿Desea continuar?"
- `signingPdfWithUnregisteredSigns` → `allowCosigningUnregisteredSignatures`
- `signingModifiedPdfForm` → `allowModifiedForm`
- `pdfShadowAttackSuspect` → `allowShadowAttack`: "El PDF es sospechoso de haber sido modificado tras la última firma. ¿Desea continuar?"
- `pdfpasswordprotected` (password prompt) → `ownerPassword` or `userPassword`
- `pdfbadpassword` (password prompt) → `userPassword`
- `signingLts` / `signingLtsPossible` → `allowSignLTSignature`
- `agePolicyIncompatibilitySign` / `…Cosign` / `…CounterSign` → `avoidAGEPolicyIncompatibilities`
- `xPathNotFound` → `allowXadesEnvelopedWithoutXPath`

In multi (headless) mode all of these make the file fail.

### 2.8 Result screens

#### 2.8.1 Validation of the generated signature (`SimpleAfirma.showResultsInfo`, single)
- The "Abrir archivo a firmar" menu item is disabled.
- The validator is chosen by content (`SignValiderFactory.getSignValider(bytes)`): PDF → PDF validator; FacturaE or XML → XML validator; OOXML or ODF → none; else binary.
- For the binary validator: if the *input* was itself a CAdES signature, validate against the data extracted from the new signature. Otherwise validate against the input file bytes. The PDF validator gets the sign config's extra params plus `checkCertificates=true`.
- If the first status is KO or UNKNOWN, those statuses are shown. Otherwise a single `GENERATED` status is shown.
- **Gotcha (apparent bug)**: for OOXML and ODF output there is no validator, the list is empty, and `get(0)` throws. The exception is swallowed by the background task, so the result screen never appears even though the file was saved. A reimplementation should show GENERATED or UNKNOWN instead.

#### 2.8.2 Single result (`SignDetailPanel`)
Vertical layout with 11 px insets: `SignResultPanel` (header), `SignDataPanel` (details), the button `"Firmar más ficheros"` (`SignDetailPanel.0`, mnemonic m, centred, initially focused; it goes back to a fresh empty SIGN panel with `loadMainApp()`), and the plugin strip (`SINGLE_RESULT`). On Windows without high contrast the background is `DEFAULT_COLOR`.

**`SignResultPanel`** (header; also used by the viewer and the multi result):
- Big icon on the left (`ScalablePane`, min 120×120): `ok_icon_large.png` for OK/GENERATED, `ko_icon_large.png` for KO, `unknown_icon_large.png` otherwise.
- Title (26 pt), description (HTML paragraph), and up to two links: the VALIDe URL `https://valide.redsara.es/` (`SignResultPanel.33`, opened in the browser; failure → `SignResultPanel.0` + URL) and `"Detalles de la firma"` (`.38`, opens `ValidationInfoDialog` for the signature bytes).
- On Windows without high contrast the background is `SECUNDARY_COLOR` (white).

| Status (first element) | Single-sign title / description / links | Multi (batch) title / description / links | Icon tooltip |
|---|---|---|---|
| GENERATED | `.2` "Proceso de firma completado satisfactoriamente" / `.3` "La firma es correcta en cuanto a estructura, pero para determinar su completa validez legal debe comprobar además la validez de los certificados usados. Para ello, puede validar esta u otras firmas electrónicas en:" / VALIDe + Detalles | – | `.4` |
| OK | `.8` "Firma electrónica válida" / `.9` / Detalles + VALIDe | `.27` "Proceso finalizado correctamente" / `.28` "Todas las firmas se han generado correctamente. Puede validar estas u otras firmas electrónicas en:" / VALIDe | `.10` (single), `.29` (multi) |
| KO | `.5` "La firma no es válida o no está soportada" / error text (below) / Detalles | `.30` "Proceso finalizado con errores" / `.31` "Ocurrió un error al firmar uno o varios de los documentos seleccionados…" / VALIDe | `.6` (single), `.32` (multi) |
| UNKNOWN, PENDING | `.11` "No se ha podido completar la validación" / error text (below) / Detalles | (same) | `.13` "Se desconoce la validez de la firma" |

All keys in this table are `SignResultPanel.*`.

KO error texts (single): CORRUPTED_SIGN `.14` "Firma electrónica corrupta."; CERTIFICATE_EXPIRED `.16`; CERTIFICATE_NOT_VALID_YET `.17`; CERTIFICATE_PROBLEM `.18`; NO_MATCH_DATA `.19`; CRL_PROBLEM `.20`; ALGORITHM_NOT_SUPPORTED `.22`; MODIFIED_FORM `.35`; MODIFIED_DOCUMENT `.36`; OVERLAPPING_SIGNATURE `.37`. Anything else, or no error, gives `.6` "La firma electrónica seleccionada no es válida".

UNKNOWN error texts: NO_DATA `.15`; CANT_VALIDATE_EXTERNALLY_DETACHED `.39`; SIGN_PROFILE_NOT_CHECKED `.40`; PDF_UNKOWN_VALIDITY `.24` "Compruebe la validez de la firma en su aplicación de lectura de PDF."; OOXML_UNKOWN_VALIDITY `.25`; ODF_UNKOWN_VALIDITY `.26`. Anything else gives `.12`.

**`SignDataPanel`** (details, also used by the viewer):
1. Label `"Fichero firmado:"` (`SignDataPanel.2`), then a bordered box (white background) containing:
   - type icon by content: PDF `icon_pdf.png`, FacturaE `icon_facturae.png`, OOXML `icon_office_win.png`, ODF `icon_openoffice.png`, else `icon_sign.png`
   - the absolute signature path, or `"Datos en memoria"` (`.24`); right-click on it gives `"Copiar la ruta del fichero"` (`.30`, copies to the clipboard)
   - button `"Ver fichero"` (`.3`, mnemonic c, 150×24) only for PDF, OOXML and ODF with a file; it opens the file with the OS application. Failure shows `.7`.
2. If a certificate is known: label `"Certificado de firma utilizado:"` (`.21`) and a bordered box:
   - certificate icon: `dnie_cert_ico.png` if the issuer DN contains `AC DNIE`, else `default_cert_ico.png`. Tooltip `"Certificado de DNI electrónico"` or `"Certificado X.509v3 genérico"`.
   - `"Titular del certificado: "` (`CertificateInfo.1`) + holder **as a link**. For DNIe the holder is `"Certificado de firma de DNIe de <GIVENNAME SURNAME>"` (`DnieCertAnalyzer.2`, `.0`); otherwise the subject CN. The link writes the DER certificate to a temp file `afirma*.cer` (deleted on exit) and opens it with the OS certificate viewer. Failure shows `.23`.
   - `"Emisor del certificado: "` (`CertificateInfo.2`) + issuer CN in bold.
3. Label `"Datos de la firma:"` (`.22`) and a bordered, scrollable **tree**. The root is hidden and every row is expanded:
   - `"Formato de firma"` (`.25`) → the format string from the signer's sign info.
   - `"Datos firmados"` (`.26`) → the link `"Ver datos firmados"` (`.28`), or `"La firma no contiene los datos firmados"` (`.27`). If the extracted data is Base64 whose decoded content has a recognisable MIME type, the decoded bytes are used.
   - `"Árbol de firmas del documento"` (`.29`) → the signer hierarchy (counter-signatures nested). Each node shows `CN (dd/MM/yyyy HH:mm)` or `CN (TimeStamp: <date>)` and is a link that opens that signer's certificate. If there is no tree: `"No se han encontrado firmantes"` (`.32`).
   - `"Sellos de tiempo"` (`.42`), only if any → one node per timestamp: `TSA-cert-CN (<gen time>)`. Timestamp sources: CMS signer unsigned attribute `signatureTimeStampToken`, and for PDFs every signature dictionary's embedded CMS timestamps plus document timestamps (SubFilter `ETSI.RFC3161` or `DocTimeStamp`). A password-protected PDF prompts `"Por favor, introduzca la contraseña del PDF"` (`TimestampsAnalyzer.0`).
   - Link nodes are rendered blue and underlined; when focused, white on `#39698a` (yellow on blue in high contrast). Hovering a link node shows the hand cursor, clicking it activates it, and **Enter/Space** activates the selected node. When the tree regains focus, the previous selection is restored. On Linux the collapsed and expanded icons come from the L&F; on Windows and macOS there are none.

**"Ver datos firmados"** (`ShowFileLinkAction` → `DataFileInfoDialog`), titled `"Datos firmados"` (`DataFileInfoDialog.3`):
- Icon by extension (`resources/file_icons/`): xml, pdf, txt, office (docx/xlsx/pptx/ppsx), odf (odt/odp/ods/odg/odc/odf/odb/odi/odm), image (jpg/jpeg/png/gif); else default.
- `"Tipo de documento:"` + MIME description, or `"Desconocido"` when it is unknown or `binary`.
- `"Extensión:"` + extension, or `"Desconocida"`.
- `"Tamaño:"` + `N bytes` (< 1 KiB), `N KB`, or `#,###.# MB`.
- Buttons: Windows `[Abrir][Guardar][Cancelar]`; other OSes `[Cancelar][Abrir][Guardar]`. "Abrir" appears only if the extension is known and not executable.
  - Abrir writes the temp file `afirma*.<ext>` and opens it with the OS. Failure shows `ShowFileLinkAction.2`.
  - Guardar opens the save dialog `"Guardar datos"` with proposed name `"documento.<ext>"`.

#### 2.8.3 Multi result (`SignResultListPanel` + `MassiveResultProcessPanel`)
- Header `SignResultPanel` with status OK if every config has a `signatureFile`, else KO, and `singleSign=false`.
- `"Directorio de firmas:"` (`MassiveResultProcessPanel.3`), then a bordered box with the output directory path (right-click `"Copiar la ruta del directorio"` `.2`) and button `"Abrir directorio"` (`.4`, mnemonic b; opens the folder with the OS file manager; failure shows `.8`).
- Signing certificate box, same as in 2.8.2.
- A bordered table with header `"Fichero"` / `"Tamaño"` / `"Estado"` (`.9/.10/.11`). Rows:
  - successful: type icon, the signature path relative to the shortest output parent + 1, size in KB, and a small `ok_icon_large.png` (32 px)
  - failed: the input's **absolute** path, `0 KB`, and the `ko_icon_large.png` icon.
- Double-click or Enter on a successful row opens it in the viewer as a modal dialog over the main window.
- Button `"Firmar más ficheros"` (mnemonic m) goes back to SIGN. Plugin strip `MULTI_RESULT`.

### 2.9 Signature details / validation dialog (`ValidationInfoDialog` + `signdetails/**`)
Modal dialog, resizable, preferred size 780×550, titled `"Detalles de la firma y errores de validación"` (`ValidationInfoDialog.0`). It contains the label `"Información sobre la firma:"` (`.1`), a read-only HTML pane and a `"Cerrar"` button (`TrustedCertificatesDialog.28`). The analyzer is chosen by content: PDF → `PAdESSignAnalyzer`; FacturaE → `FacturaESignAnalyzer`; any other signature whose signer is XAdES → `XAdESSignAnalyzer`; else → `CAdESSignAnalyzer`. If analysis fails it shows the error `"No se ha podido leer correctamente el fichero de firma."` (`.17`). Gotcha: the formatter then dereferences the null analyzer, so ODF and OOXML signatures, which go to the CAdES analyzer, crash this dialog. A reimplementation should handle them.

Model (`SignDetails` per signature):
- `signProfile`: from the format detectors, e.g. `AdES-BES`, `PAdES-Basic`, `XAdES-T`.
- `algorithm`, `signingTime`.
- `policy`: (name, identifier, hash, hash algorithm, qualifier).
- `metadata` map: localized keys such as Calle, Código postal, Ciudad, Localidad, Estado o provincia, País, Razón de firma, Localización, Información de contacto, plus `claimedRoleN`.
- `dataObjectFormats`: (identifier, description, mimeType, encoding).
- `validityResult`: `List<SignValidity>`.
- `signer` (`CertificateDetails`): CN, issuer CN, expiry `dd-MM-yyyy`, validity map `{"Validación": msg}`. The message is `"Correcta. No se ha realizado la comprobación de revocación del certificado."` (`.40`) if the certificate is time-valid, otherwise `.2` "Certificado caducado.", `.3` "Certificado no válido aún.", `.4` or `.5` (key incompatible with the declared algorithm).
- PAdES only: `certificationLevel`, `certificationSign`, `lastRevisionSign`.

Analyzer specifics:
- **CAdES**:
  - one entry per SignerInfo, recursing into counter-signatures
  - MIME from the `contentHint` OID through `resources/mimetypes_oids.properties`
  - signing time from the `signingTime` attribute
  - policy from `sigPolicyId`: AGE 1.9/1.8 recognised by OID, otherwise custom
  - roles from signer-attr v1/v2
  - location (country, postal code, locality) from `signerLocation`
  - algorithm = `<digest>with<keyAlg>`
  - data location `"La firma contiene los datos."` (`.21`) or `"La firma no contiene los datos."` (`.22`).
- **XAdES**:
  - one entry per `ds:Signature` not nested in a timestamp
  - the signature-method URI is mapped to `SHA{1,256,384,512}with{RSA,ECDSA}`
  - supported XAdES namespaces: no-version, 1.2.2, 1.3.2, 1.4.1; any other is rejected
  - `SigningTime` parsed as `yyyy-MM-dd'T'HH:mm:ss`
  - DataObjectFormat entries, policy (AGE 1.8/1.9 by identifier, else custom with SPURI), production place (v1 or v2), signer roles (v1 or v2)
  - data location: enveloped `.12` "La firma se encuentra dentro del XML firmado.", manifest `.16`, externally detached `.22`, internally detached `.14` "Datos anexos a la firma.", enveloping `.21`.
- **PAdES**:
  - one entry per AcroForm signature, skipping document timestamps
  - signers tree built as `CN (date)`
  - reason, location and contact from the signature dictionary
  - policy from the embedded CMS
  - validity per signature from the PDF validator; for certification level 1 ("no changes"), a valid signature that is not on the last revision becomes `KO / CERTIFIED_SIGN_REVISION`.
- **FacturaE**: like XAdES; the format label is `"Factura Electr&oacute;nica"`.

HTML layout produced by `SignDetailsFormatter.formatToHTML`:
1. `Formato: <fmt>`; `Localización de los datos: <loc>`; `Información sobre datos firmados:` with a list of Encoding/Descripción/Tipo de documento per data-object format. MIME types are mapped to friendly names, e.g. `application/pdf`→PDF, `text/xml`→XML, `image/jpeg`→JPEG, `application/msword`→Microsoft Word.
2. `Árbol de firmantes:` as a nested list of `Firma N: <node>`.
3. `Resultado de la validación: <overall>` (`validityTypeToString` of the first status), followed by a bullet list of:
   - global errors of type MODIFIED_FORM, MODIFIED_DOCUMENT, OVERLAPPING_SIGNATURE, SUSPECTED_SIGNATURE, CANT_VALIDATE_EXTERNALLY_DETACHED or NO_DATA
   - per-signature errors as `Firma i: <validity>`, excluding certificate errors (they are reported via the certificate)
   - per-signature certificate messages that are not "Correcta…".
4. For each signature: `<h1>Firma i : <CN></h1>` and a block with:
   - `Perfil de firma` (omitted for FacturaE)
   - `PDF certificado` (PAdES, if it is a certification signature): level 1 `.41` "No se admiten cambios.", level 2 `.42`, level 3 `.43`
   - `Algoritmo de firma`, `Fecha y hora de firma` (`dd/MM/yyyy HH:mm:ss`)
   - `Resultado de la validación` list, if not OK
   - `Política de firma`: just the name for known policies (FacturaE 3.0/3.1, AGE 1.8/1.9 for XAdES/CAdES, AGE 1.9 for PAdES); otherwise Descripción/Identificador/Hash/Algoritmo/Calificador
   - `Metadatos`: Roles (comma-joined), address fields, reason, location, contact
   - `Certificado`: Nombre, Emisor, Fecha de caducidad, Resultado de la validación (key: value).

**Validity categories** (`SignValidity`, module afirma-crypto-validation, bundle `validationmessages`). They are used everywhere:

| `SIGN_DETAIL_TYPE` | Text (`SignValidationMessage.N`) | Icon / colour |
|---|---|---|
| OK, GENERATED | `.0` "Firma válida" | `ok_icon*.png` (green tick) |
| KO | `.3` "Firma no válida" | `ko_icon*.png`, red text in lists |
| UNKNOWN | `.1` "Validación incompleta" | `unknown_icon*.png`, red text in lists |
| PENDING_CONFIRM_BY_USER | `.2` "Validez a confirmar por el usuario" | `unknown_icon*.png`, red text |

`SignValidity.toString()` = type text + `": "` + error text. Error texts: NO_DATA `.4`, CORRUPTED_SIGN `.5`, NO_MATCH_DATA `.6`, NO_SIGN `.7`, CERTIFICATE_PROBLEM `.8`, CERTIFICATE_EXPIRED `.9`, CERTIFICATE_NOT_VALID_YET `.10`, CANT_VALIDATE_CERT `.11`, ALGORITHM_NOT_SUPPORTED `.12`, CA_NOT_SUPPORTED `.13`, CRL_PROBLEM `.14`, PDF/OOXML/ODF_UNKOWN_VALIDITY `.15/.16/.17`, UNKOWN_ERROR `.18`, UNKOWN_SIGNATURE_FORMAT `.19`, MODIFIED_DOCUMENT `.20`, OVERLAPPING_SIGNATURE `.21`, MODIFIED_FORM `.22`, SUSPECTED_SIGNATURE `.23`, SIGN_PROFILE_NOT_CHECKED `.24`, CANT_VALIDATE_EXTERNALLY_DETACHED `.25`, BAD_BUILD_SIGN `.26`, CERTIFIED_SIGN_REVISION `.27`. The texts contain HTML entities (`&oacute;`). The validation algorithms themselves are specified elsewhere.

### 2.10 Signature attributes dialog (`SignatureAttributesDialog`)
A plain information dialog titled `"Atributos de firma"` (`SignatureAttributesDialog.0`).

If the extra params contain any of `policyIdentifier`, `signatureProductionStreetAddress`, `…City`, `…Province`, `…PostalCode`, `…Country`, `signerClaimedRoles`, `signerContact` or `signReason`, the dialog shows the intro `.1` ("Además de los datos, la fecha y hora y el certificado de firma que seleccione, la firma electrónica del documento incluirá los siguientes atributos:") and these bold sections with indented label/value rows:
- `"Política de firma:"` (`.2`): Identificador `.3`, Huella digital `.4` (`policyIdentifierHash`), Algoritmo de huella `.5`, Descripción `.6` (`policyDescription`), Referencia `.7` (`policyQualifier`).
- `"Lugar de firma:"` (`.8`): Dirección `.9` (only if `profile` = `B-B-Level`), Ciudad `.10`, Provincia `.11`, Código postal `.12`, País `.13`.
- `"Información adicional:"` (`.19`): Razón de firma `.17`, Información de contacto `.18`.
- `"Rol de firma:"` (`.14`): Roles declarados `.15`.

Otherwise it shows `.16` ("La firma se realizará sobre los datos del documento, la fecha y hora y el certificado de firma que seleccione. No se han definido atributos de firma adicionales.").

### 2.11 Signature viewer (`VisorFirma` + `VisorPanel`)
- `VisorFirma(standalone, parent)` first applies the look & feel and the locale from preference `default.locale`.
- Without a parent it opens its own `MainScreen` frame (780×650) titled `"Visor de firmas electrónicas - <absolute path>"` (`VisorFirma.0`), maximised on small screens. With a parent it opens an application-modal `JDialog` of the same size. Quirk: the dialog is positioned using the width for both axes.
- Closing the window disposes it and, **only if `standalone`**, exits the process with code 0.
- Content (`VisorPanel`, 15 px border):
  1. `SignResultPanel(validity, singleSign=true)`.
  2. `SignDataPanel(file, bytes, cert)`. The certificate box is shown only if the signature has **exactly one** top-level signer; that signer's first certificate is used. Signer sniffing order for this: FacturaE, XAdES, XMLDSig, PDF, CAdES, CMS, OOXML, ODF.
  3. A right-aligned button row:
     - `"Ver otra firma"` (`VisorPanel.1`, mnemonic V), **only in standalone mode**. It opens a file chooser `"Abrir"` (`VisorFirma.1`) and reinitialises the viewer with the chosen file.
     - `"Cerrar visor"` (`VisorPanel.0`, mnemonic C).
     - ESC pressed on either button closes the viewer.
  4. Plugin strip `VISOR`.
- Validation (`VisorPanel.validateSign`): validator chosen by content (see 2.8.1). OOXML/ODF signatures give `UNKNOWN / OOXML_UNKOWN_VALIDITY|ODF_UNKOWN_VALIDITY`. An empty result gives `KO / UNKOWN_SIGNATURE_FORMAT`. A validation exception gives `KO`. Unreadable bytes give `UNKNOWN`.
- Entry points:
  - menu "Ver firma": chooser titled `"Abrir firma"` (`MainMenu.35`), filter `"Firmas electrónicas"` (`MainMenu.36`) with extensions `csig, xsig, pdf, sig, p7s`, single selection. A non-file selection gives `SignPanel.123`.
  - the "Ver Fichero" button on `.csig`/`.xsig` inputs
  - double-click or Enter on a signature row in the multi-file list or a result row in the multi result
  - CLI `verify -gui -i <file>` (standalone).

### 2.12 Menu bar (`MainMenu`)
"Menu key" means Ctrl on Windows/Linux and Cmd on macOS (`getMenuShortcutKeyMask`). Menus in order:

| Menu (mnemonic) | Item | Accelerator | Item mnemonic | Action / notes |
|---|---|---|---|---|
| `"Archivo"` (`MainMenu.0`; quirk: mnemonic set to `VK_ALT`, so effectively none) | `"Abrir archivo a firmar"` (`.2`) | Menu+A | B (not on macOS) | chooser `"Seleccione el fichero a firmar"` (`.4`); only the **first** selected file is loaded into the SIGN panel. Disabled on result screens and re-enabled when returning to SIGN |
| | `"Ver firma"` (`.34`) | Menu+V | V | opens the viewer (2.11) |
| | separator + `"Salir"` (`.7`) | Alt+F4 | L | `askForClosing()`; **absent on macOS** |
| `"Herramientas"` (`.32`) (R) | `"Restaurar instalación"` (`.20`) | Menu+R | R | `RestoreConfigDialog.show(frame, modal)` (§10) |
| | `"Gestionar plugins"` (`.37`) | Menu+G | G | `PluginsManagementDialog` (§7); afterwards the current panel's plugin strip is refreshed |
| | separator + `"Preferencias"` (`.12`) | Menu+P | P | `PreferencesDialog.show(frame, modal, tab 0)` (§4); **absent on macOS** |
| `"Idioma"` (`.38`) | radio items `Español`, `Catalá`, `Galego`, `Euskera`, `Valencià`, `English` (`.39, .41, .42, .43, .44, .40`) for locales `es_ES, ca_ES, gl_ES, eu_ES, va_ES, en_US` | – | – | selected = preference `default.locale` (default `es_ES`). Choosing one stores the preference, reloads bundles and shows the restart prompt |
| | imported languages (radio), except updated versions of built-in locales | – | – | same; data from `LanguageManager` (§11) |
| | separator + `"Importar idioma"` (`.45`) | Menu+I | – | zip chooser `"Abrir fichero para importar idioma"` (`.46`), filter `"Archivo comprimido (*.zip)"`; on success info `"El idioma se ha importado correctamente"` (`.52`), the item is added before the separator and selected, the locale is switched, then the restart prompt. Errors `LanguageManagementError.<code>` (codes CANT_READ_FILE, CANT_CREATE_DIRECTORY, else GENERIC_LANGUAGE_IMPORT_ERROR) |
| plugin menus (one per plugin with MENU permission) | nested submenus from the plugin's JSON; leaf items run the plugin action class with the main frame as parent. Error: `"Ocurrió un error inesperado al ejecutar la acción."` (`SimpleAfirma.52`) | | | §7 |
| (horizontal glue, so Ayuda is right-aligned except on macOS) | | | | |
| `"Ayuda"` (`.9`) (Y) | `"Ayuda de Autofirma"` (`.11`) | F1 | U (not on macOS) | `showHelp("Autofirma.html")` (§1) |
| | separator + `"Acerca de Autofirma"` (`.15`) | **Menu+C** (quirk: shadows the copy shortcut) | C | About dialog; **absent on macOS** |

Restart prompt (`showRestartWarning`): `JSEUIMessages.updateLocale()` runs first.
- If a relaunch command is available (`DesktopUtil.getResetApplicationCommand()`, §1): Yes/No warning titled `"Reiniciar Autofirma"` (`.50`) with `"Es necesario reiniciar la aplicación para que los cambios surtan efecto. ¿Desea que se reinicie la aplicación?"` (`.51`). Yes spawns the command and calls `System.exit(0)`.
- Otherwise: warning `"Reinicie la aplicación para que los cambios surtan efecto."` (`.49`).

macOS: About, Preferences and Quit are bound to the system application menu through `com.apple.eawt.Application` (Java ≤ 8) or the `java.awt.desktop.*Handler` interfaces. Quit calls `askForClosing()`. Item mnemonics are not set.

Unused legacy keys `MainMenu.18/19/24–31` (Opciones, Huellas digitales…) still exist in the bundles. The hash menu is now provided by the hash plugin (§7).

**About dialog** (`AboutDialog`): plain message box titled `"Acerca de Autofirma"`, body `MainMenu.14`: HTML with `"Autofirma %0"`, `"© 2011-2026 Gobierno de España"`, the dual GPLv2+/EUPL 1.1+ licence text, third-party components (iText 2.1.7, jMimeMagic, JUniversalCharDet, jXAdES, SpongyCastle, Java WebSockets, Proxy Vole), and `"Versión de Java actualmente en uso: %1 (%2bits)"`. A reimplementation should replace the component list with its own.

**Close confirmation** (`askForClosing`):
- If preference `omitAskOnClose` is true, exit(0) immediately.
- Otherwise a Yes/No warning titled `"Advertencia"` (`SimpleAfirma.48`) with `ClosePanel`: the text `"¿Desea cerrar la aplicación de firma?"` (`SimpleAfirma.47`) and the checkbox `"No volver a mostrar este mensaje"` (`ClosePanel.0`, mnemonic m). The checkbox **writes `omitAskOnClose` immediately on toggle**, even if the user then answers No.
- Yes disposes the window and calls `System.exit(0)`.

### 2.13 Plugin integration points in the UI (detail in §7)
- `PluginIntegrationWindow` values and their JSON `window` strings (case-insensitive): `INPUT_DATA` ← `"input"` or `"input_data"`; `SINGLE_RESULT` ← `"single_result"`; `MULTI_RESULT` ← `"multi_result"`; `VISOR` ← `"visor"`.
- Buttons (`PluginsUiComponentsBuilder.getPluginsButtons(window)`): for each loaded plugin with permission `BUTTONS`, each declared button whose window matches becomes a `JButton` with the title, an optional icon (resource loaded through the plugin's class loader), the tooltip and an accessible description. Invalid declarations are logged and skipped. The strip is rebuilt after the plugin manager dialog closes. **Every action runs on a new thread**, with the panel's top-level window as parent:

| Window | Action type receives | Content |
|---|---|---|
| INPUT_DATA (SignPanel) | `DataProcessAction.processData(InputData[], window)`; other actions `start(window)` | one `InputData` per loaded file: `dataFile`, `signatureFormat` = localized display name (2.4.4). Empty array if none |
| SINGLE_RESULT | `SignatureProcessAction.processSignatures(OutputData[1], signingCert, window)` | `dataFile` = saved signature file, `signatureFormat` = display name, `certs` = distinct first certificate of every signer node in the tree (keyed by serial number) |
| MULTI_RESULT | `processSignatures(OutputData[], signingCert, window)` | one per config: `dataFile` = signature file (**null for failed ones**), `signatureFormat`; no certs |
| VISOR | `processSignatures(OutputData[1], null, window)` | `dataFile` = viewed file, `signatureFormat` = format string from the sign info, `certs` as in SINGLE_RESULT |

- Menus: plugins with permission `MENU` contribute a `GenericMenuOption` tree. Menus are added after "Idioma" and are built only once, at menu-bar creation.
- Sign hooks (in `SignPanelSignTask`):
  - `preSignProcess(data, formatName)` for plugins with `PRESIGN`.
  - `postSignProcess(signature, formatName, certChain)` for plugins with `POSTSIGN`.
  - `reset()` on all plugins after the loop.

  Hooks are chained in plugin-list order. A `PluginControlledException` shows its message as a warning and processing continues with the unmodified bytes for that plugin. Any other throwable shows `"El plugin %0 ha devuelto un error al procesar los datos de entrada: %1"` (`SignPanel.111`), `.112` for post-sign or `.115` for reset, and continues. Failure to get the plugin list gives `SignPanel.113`/`.114` and skips the plugins.

### 2.14 Auxiliary dialogs and widgets
- **`CommonWaitDialog`**: application-modal, undecorated content with a label + indeterminate `JProgressBar` (macOS: `JProgressBar.style=circular`), 10 px padding, centred on the screen centre, not closable, not resizable. `setMessage` updates the text and repacks.
- **`ProgressInfoDialog` / `ProgressInfoDialogManager`**: undecorated rounded (20 px radius) white popup with an 18 pt centred label. It is shown **only** when the app was invoked with an `afirma://` URL whose query contains `dlgload=true`, **and** preference `enableProgressDialog` is true (default true). Never in desktop mode. Messages: `ProgressInfoDialog.0` "Comprobando firmas anteriores", `.1` "Ejecutando firma", `.2` "Cargando almacenes de claves", `.3` "Procesando petición", `.4` "Configurando conexiones seguras", `.5` "Cargando Autofirma", `.6` "Iniciando interfaz gráfica". Startup usage is in §1; protocol usage is in the protocol spec.
- **`DataDebugDialog`** (debug only): an 800×600 modal dialog titled `"Datos a firmar"` (`DataDebugDialog.4`). It shows the type, the size in bytes, and the content: raw text if the MIME type contains `text` or `xml`, else MIME-Base64 with line breaks. **Ctrl+R** in the text area loads replacement data from a file, and the button `"Continuar"` (mnemonic C) closes it. It is triggered only by the protocol sign operations when the **JVM system property** `AFIRMA_SHOW_DATA_TO_SIGN=true` is set (the code comment says environment variable, but it is a `-D` property). Optional for a reimplementation.
- **`ErrorPane`**: an error dialog with an expandable stack trace ("Ver detalles"). **Dead code** (never called); errors use `AOUIFactory.showErrorMessage` (§3).
- **`CopyMenuItem`**: a one-item popup that copies a label's text to the system clipboard.
- **`ImageLoader`**: loads `/resources/<name>`, with sizes SMALL 32, MEDIUM 64, LARGE 128, XLARGE 256 (smooth scaling).
- **`ScalablePane`**: an image panel that scales to fit while keeping the aspect ratio.
- **`RoundedPanel`**: a rounded-corner panel used by the progress popup.
- **`EditorFocusManager`**: keyboard navigation of hyperlinks inside HTML panes, used by the PDF dialogs in §3. Arrow keys move between links (wrapping around), Enter/Space activates, and the focused link is styled with the tree selection colours. In high contrast the body text colour follows the label foreground.
- **Executable extensions** (`DataFileAnalizer`; "Ver Fichero"/"Abrir" are hidden for these, case-insensitive): ACTION, APK, APP, BAT, BIN, CMD, COM, COMMAND, CPL, CSH, EXE, GADGET, INF1, INS, INX, IPA, ISU, JOB, JSE, KSH, LNK, MSC, MSI, MSP, MST, OSX, OUT, PAF, PIF, PRG, PS1, REG, RGS, RUN, SCR, SCT, SHB, SHS, U3P, VB, VBE, VBS, VBSCRIPT, WORKFLOW, WS, WSF, WSH.

### 2.15 Colours, OS-specific look, and UI-level accessibility notes
- `DEFAULT_COLOR` = the L&F `window` colour (fallback RGB 238,238,238). `SECUNDARY_COLOR` = white, or black in Windows high contrast. High contrast is detected via the desktop property `win.highContrast.on` (§1, §12). When high contrast is on, custom background colours are **not** applied: borders become white, and link colours become yellow (on blue when focused).
- Several panels apply custom backgrounds **only on Windows**: result panels, the viewer, and the details panel.
- macOS: scroll panes always show scrollbars. The drop zone's surrounding scroll background stays white.
- Every interactive custom widget (link labels, tree link nodes, result lists) is keyboard operable: **Enter/Space** activates, **Enter** opens list rows, **ESC** closes the viewer and skips the DNIe screen, **F1** opens help. Each widget carries accessible names and descriptions; the descriptions are concatenations of the visible texts and are re-generated when panels are built.
- Quirk: several panels start their accessible-description string as `null`, so the text begins with `"null…"`. Do not replicate this.

### 2.16 Notable quirks to decide on (summary)
1. The `sign -gui` path loses the preference-derived and CLI extra params (2.4.2).
2. The multi-sign operation always comes from preferences; there is no UI choice (2.4.8).
3. In multi-file mode the certification level is read under the wrong preference (`padesVisibleSignature`) (2.7).
4. No result screen after OOXML/ODF signing; the details dialog crashes for those formats (2.8.1, 2.9).
5. Missing message keys `SignPanel.161/162` (locked keystore, authentication error).
6. The wrong key `SignPanel.123` is used for "unsupported key type".
7. The "No volver a mostrar" checkboxes in the close and DNIe dialogs persist their preference immediately, even when the dialog is answered No.
8. The "Abrir" accelerator is Menu+A (the Javadoc says Ctrl+B). "Acerca de" uses Menu+C.
9. Dropped or selected directories are expanded recursively with no filter, and every file is read fully into memory.
10. JVM system properties are merged into every signature's extra params.


## 3. GUI: PDF visible signature, certificate selection, keystores, generic dialogs

This section covers (a) the PDF visible-signature / visible-stamp dialogs used before a PAdES signature, (b) how the
application chooses, loads and switches keystores, (c) the certificate selection dialog, (d) background tasks that
prepare keystores / TLS, and (e) the generic dialogs (password, confirm, open/save file, error) supplied by
`afirma-ui-core-jse`. Preference keys are only *referenced* here; their full definition (type, default, UI location,
locking) is in §4. The PDF signing engine itself (how `layer2Text` placeholders are expanded, how the appearance is
drawn, obfuscation, etc.) belongs to the PAdES spec; here we specify the exact extra-params the UI emits.

Message keys quoted below come from:

| Bundle (base name) | File | Used by |
|---|---|---|
| `properties.signpdfuimessages.signpdfuimessages` | `afirma-simple/src/main/resources/properties/signpdfuimessages/signpdfuimessages_<ll_CC>.properties` | all `ui/pdf/*` classes (`SignPdfUiMessages`) |
| `properties.simpleafirmamessages.simpleafirmamessages` | `afirma-simple/.../simpleafirmamessages/*.properties` | `SimpleAfirmaMessages` |
| `certdialogmessages.certdialogmessages` | `afirma-ui-core-jse-keystores/src/main/resources/certdialogmessages/*.properties` | certificate selection dialog |
| `uimessages.uimessages` | `afirma-ui-core-jse/src/main/resources/uimessages/*.properties` | `JSEUIManager` generic dialogs |
| `keystoremessages` | `afirma-core-keystores/src/main/resources/keystoremessages/*.properties` | `AOKeyStore`, `AOKeyStoreDialog` |
| `coremessages` | `afirma-core/src/main/resources/resources/coremessages/*.properties` | `KeyUsage` texts |
| `jmulticarduimessages` | `afirma-keystores-jmulticard-ui/.../jmulticarduimessages/*.properties` | smart-card PIN dialogs |

All bundles exist for `ca_ES, en_US, es_ES, eu_ES, gl_ES, va_ES` (see §11). `SignPdfUiMessages.getString(key, params…)`
substitutes `%0`, `%1`, … literally; a missing key renders as `!key!`.

---

### 3.1 Entry points for the visible-signature UI

There are two independent callers. Both use the same dialog (`SignPdfDialog`) but with different flags and different
cancel semantics.

| Caller | Class | When | Flags passed to `SignPdfDialog` |
|---|---|---|---|
| Desktop GUI (single or multi-file signing) | `ui/SignPanel.signOperation…` → `VisiblePdfSignatureManager.getVisibleSignatureParams()` | At least one selected file will be signed with `AOPDFSigner` (PAdES) | `signatureVisible` = checkbox/pref, `customAppearance` = **always true**, `stampVisible` = checkbox (single file only) |
| Protocol `afirma://sign` / `signandsave` (and batch through the same launchers) | `protocol/ProtocolInvocationLauncherSign.showRubricPositionDialog()` (identical code in `ProtocolInvocationLauncherSignAndSave`) | Format is one of `PDF`, `PDFtri`, `PAdES`, `PAdEStri`, `PAdES-BES` (`AOSignConstants.PADES_SUBFILTER_BES`), `PAdES-basic`/`PADES_SUBFILTER_BASIC` **and** extra-param `visibleSignature` = `want` or `optional` (case-insensitive) | `signatureVisible=true`, `customAppearance = (extraParam visibleAppearance equalsIgnoreCase "custom")`, `stampVisible=false`, parent = none |

#### 3.1.1 Desktop GUI decision (SignPanel)

Executed after the "confirm before signing" dialog and after multisign configuration (see §2):

1. If no config uses the PDF signer → sign immediately (no dialog).
2. Show wait text `SignPanelSignTask.0` = "Creando previsualización del PDF. Esta tarea puede tardar varios minutos." in the
   sign wait dialog.
3. Determine flags:
   * Single-file mode (lower panel is `SignPanelFilePanel`): `visibleSignature` = checkbox "Hacer la firma visible dentro
     del PDF" (`SignPanel.44`, initial value = pref `padesVisibleSignature`); `visibleStamp` = checkbox "Insertar una
     marca visible dentro del PDF" (`SignPanel.120`, initial = pref `padesVisibleStamp`; disabled with note
     `SignPanel.121` "No se pueden aplicar marcas visibles a documentos ya firmados" when the operation is a co-sign of
     an already-signed PDF); `certificationLevel` = the "certified PDF" combo when the checkbox is ticked (only shown
     if pref `allowCertifiedPDF` is true).
   * Multi-file mode: `visibleSignature` = pref `padesVisibleSignature`; `visibleStamp` = false;
     `certificationLevel` = pref `padesCertificationLevel` **if pref `padesVisibleSignature` is true**.
     *Quirk:* the code reads `padesVisibleSignature` where it obviously meant `allowCertifiedPDF`. A reimplementation
     should gate on `allowCertifiedPDF`.
4. If `certificationLevel` is non-null and ≠ `"0"`, add extra-param `certificationLevel=<1|2|3>` to **every** config.
5. Clone all sign configs (so a cancelled dialog does not leave params behind) and call
   `VisiblePdfSignatureManager.getVisibleSignatureParams(clones, executor, visibleSignature, visibleStamp, mainWindow)`.
6. Exceptions: `AOCancelledOperationException` → close the wait dialog and abort the signature. Any other exception →
   log "No se pudo crear la firma visible PDF, se creara una firma invisible" and **sign invisibly** with the clones.

#### 3.1.2 VisiblePdfSignatureManager algorithm

```
pdfConf  = first config whose signer is the PDF signer
data     = bytes of pdfConf.dataFile
fields   = PdfUtil.getPdfEmptySignatureFields(data)   // blank AcroForm signature fields with a widget position
if fields not empty:
    field = PdfEmptySignatureFieldsChooserDialog.selectField(fields)    // may throw Cancelled
    if field == null (user chose "create new field"):
        if visibleSignature or visibleStamp: showDialog(signatureVisible, stampVisible)
        else: sign now
    else:
        add extra-param signatureField=<field name> to ALL configs (not only PDF ones)
        if visibleStamp: showDialog(signatureVisible=false, stampVisible=true)   // area comes from the field
        else: sign now
elif visibleSignature or visibleStamp:
    showDialog(signatureVisible, stampVisible)
else:
    sign now
```

`showDialog` calls `SignPdfDialog.getVisibleSignatureExtraParams(isSign = signer.isSign(data) of the FIRST config,
isMassive = configs.size() > 1, data, parent, signatureVisible, customAppearance=true, stampVisible, listener)`.
The listener (`SignPdfListener`) receives a `Properties`; if non-empty, it is merged into **every config whose signer is
the PDF signer** (so the same position/appearance is reused for all PDFs in a multi-file signature); then the signature
task starts.

**Gotcha (cancel = invisible signature in GUI mode):** when the user cancels/closes `SignPdfDialog`, the listener receives
an *empty* `Properties` and the code still starts the signature task, i.e. the PDF is signed **without** visible
signature (but with `signatureField` if one was chosen). Only the "Cancelar firma" button of the empty-field chooser
aborts. A reimplementation should decide explicitly (recommended: Cancel aborts; offer "Sign without visible
signature" as a separate button).

Empty-field detection (`PdfUtil.getPdfEmptySignatureFields`): open the PDF (no password); for each name returned by
AcroFields "blank signature names", take the first widget position `[page, llx, lly, urx, ury]` (floats rounded to int);
skip fields without position. Unreadable PDF → empty list. Encrypted PDFs that need a password therefore never offer
field selection (quirk).

### 3.2 Empty signature field chooser (`PdfEmptySignatureFieldsChooserDialog.selectField`)

A standard modal option dialog (parent = none):

* Title: `SignPanelSignTask.1` = "Selección de campo PDF para firma visible".
* Body: label `SignPdfFieldChooser.7` = "Se ha detectado un campo de firma vacío en el documento. Seleccione el campo en
  el que desea insertar la firma o si desea agregarla en un nuevo campo." + combo box listing the field **names**
  (in document order).
* Buttons (in this order, first is default): `SignPdfFieldChooser.4` "Usar campo seleccionado" → returns the selected
  field; `SignPdfFieldChooser.6` "Crear campo nuevo" → returns null; `SignPdfFieldChooser.5` "Cancelar firma" →
  throws Cancelled (signature aborted).
* *Quirk:* closing the window with the title-bar X returns index −1, which is treated as "Crear campo nuevo".

The same class also contains a full dialog (`startPdfEmptySignatureFieldsChooserDialog`, 500×615, application-modal,
title `SignPdfDialog.3`) which previews the field area and opens the appearance editor (§3.6) pre-filled with
`signatureField`, `signaturePage=<field page>` and the four `signaturePositionOnPage*` values taken from the field; if a
stamp is also wanted it continues to the stamp panel. **It is not called anywhere** in the current code (dead code);
do not reimplement unless desired. (Its preview crop uses the 75-DPI image with PDF-point coordinates and no Y-flip,
i.e. it is buggy.)

### 3.3 `SignPdfDialog` – the container dialog

* Title `SignPdfDialog.3` = "Propiedades de la firma visible PDF" (changed to `SignPdfUiStamp.0` = "Propiedades de
  marca visible" when it opens directly on the stamp panel). Accessible description `SignPdfDialog.2`. Window icons =
  application icons. Modality: toolkit-modal. Content = a scroll pane (unit increment 16 px both axes) whose viewport
  hosts the active panel.
* Preferred size: width **500**, height `min(800, 0.9 × screenHeight)` for signature panels; `min(860, 0.9 ×
  screenHeight)` for the stamp panel. Centered on the screen centre point.
* Closing the window (X) = cancel (`positionCancelled` → listener gets empty properties).
* Loading: `PdfLoader.loadPdf()` starts a **new thread** that calls `pdfLoaded()`; the dialog becomes visible only after
  the first page images are rendered (meanwhile the caller's wait dialog is shown). `OutOfMemoryError` or `IOException`
  → `pdfLoadedFailed`.
* PDF password: rendering is retried in a loop; on `InvalidPasswordException` the user is prompted with the generic
  password dialog (§3.13.2) using `pdfpasswordprotected` = "El PDF está protegido por contraseña. Introduzca de la
  contraseña del PDF." the first time and `pdfbadpassword` = "La contraseña introducida es incorrecta. Introduzca de la
  contraseña del PDF." afterwards. Cancel → failure. When a password was used, extra-param
  `ownerPassword=<password>` is put in the initial properties (so it ends in the final params).
* Failure dialog (`pdfLoadedFailed`): error dialog, title `SignPdfDialog.1` "Error cargando el documento PDF"; message
  `SignPdfDialog.4` ("El fichero es demasiado grande para generar firma visible. Pruebe a generar una firma
  invisible.") for OOM, otherwise `SignPdfDialog.0` ("No se ha podido crear la previsualización del PDF. Inténtelo de
  nuevo y si el problema persiste genere firmas invisibles."). Then listener gets empty properties (→ invisible
  signature in GUI mode, see gotcha above).

#### 3.3.1 Panel state machine

| Current panel | Event | Next |
|---|---|---|
| (load) | `signatureVisible` | Area panel (§3.5) |
| (load) | `!signatureVisible && stampVisible` | Stamp panel (§3.7) |
| Area panel | "Siguiente" and area valid | if `customAppearance` → Appearance panel (§3.6) (and, if the preloaded rubric image from prefs has transparency, warn `SignPdfDialog.9`); else finish with area params |
| Area panel | "Siguiente" and area too small | error `SignPdfDialog.6` "El área seleccionada para mostrar la firma tiene un tamaño demasiado pequeño." / title `SignPdfDialog.7` "Tamaño inválido"; stay |
| Appearance panel | "Aceptar" and `stampVisible` | Stamp panel, initialised with the accumulated properties |
| Appearance panel | "Aceptar" and `!stampVisible` | finish |
| Stamp panel | "Aceptar" | finish |
| any | "Cancelar", Esc, window close | cancel (listener gets empty `Properties`) |

Area validity (`checkSignatureDimensions`, PDF units): with `w = |urx−llx|`, `h = |ury−lly|`: invalid if `w < 30` or
`h < 45` or `w×h < 1350`.

"Finish" logs `Propiedades establecidas mediante GUI: <props>` (note: this logs base64 images and the PDF owner password
– avoid in reimplementation) and hands the properties to the listener.

### 3.4 Page rendering (`Pdf2ImagesConverter`, `PdfDocument`, `SignPdfUiUtil`)

* Rendering engine: Apache PDFBox `PDFRenderer.renderImageWithDPI(page, 75, RGB)` — **75 DPI**, RGB, one image per page.
* Lazy window: the list has one slot per page; only these pages are rendered (0-based index `i`): `i < 4` (first four),
  `i >= n−4` (last four), `|i − current| <= 4`. Other slots are null. On page navigation (`PdfDocument.loadNewPages` →
  `updateUsefulSections`) the window is recomputed around the new page: missing pages are rendered, pages outside the
  window are dropped (set to null). *Quirk:* the re-render opens the PDF **without** the password, so navigating far
  into an encrypted PDF fails with `SignPdfDialog.5` "No se ha podido crear la previsualización de la nueva página."
* Page sizes (`SignPdfUiUtil.getPageSizes`): with the iText-derived `PdfReader` (owner password as UTF-8 bytes if any),
  `getPageSizeWithRotation(i)` for each page → `(round(width), round(height))` in PDF points, **after applying /Rotate**.
* `getScreenBounds` (usable desktop bounds minus insets) is provided but unused by the dialogs.

### 3.5 Signature area panel (`SignPdfUiPanel` + `PageLabel`)

Layout (preferred 470×720), top to bottom:

1. Titled border `SignPdfUiPanel.7` "**Posición de firma**" containing:
   * message label: `SignPdfUiPanel.14` "Inserte o seleccione el área de firma visible." (single PDF) or
     `SignPdfUiPanel.20` "Inserte o seleccione el área de firma visible para todos los documentos." (multi-file);
   * coordinates row: `X:` [4-col field] `Y:` [field] `Anchura:` [field] `Altura:` [field]
     (`SignPdfUiPanel.8/.9/.12/.13`, accessible descriptions `.16`–`.19`). Each field accepts **only digits, max 4
     characters** (`NaturalNumbersDocFilter`); focus selects all text, focus-lost deselects;
   * page preview area (466×400 container) holding the current page image (`PageLabel`), crosshair cursor, accessible
     description `SignPdfUiPanel.6` "Previsualización de la página actual del PDF";
   * pagination row: buttons `<<`, `<`, label `SignPdfUiPanel.5` = "Página %0 de %1 (escala: %2%)", `>`, `>>`.
2. Titled border `SignPdfUiPanel.22` "**Página de firma**" with a radio group:
   * `SignPdfUiPanel.23` "Página actual" (default, selected);
   * `SignPdfUiPanel.24` "Todas las páginas";
   * `SignPdfUiPanel.25` "Selección de páginas" + free-text field (enabled only when this radio is selected) + help
     icon button (`/resources/toolbar/ic_help_black_18dp.png`, white variant under Windows high-contrast; tooltip/a11y
     `SignPdfUiPanel.27`) that opens the help page `pgs/VentanaPdfVisible.html` (see §1/§11 help system).
3. Buttons (right aligned): "Siguiente" (`SignPdfUiPanel.0`, mnemonic **A**, disabled until an area exists) and
   "Cancelar" (`SignPdfUiPanel.3`, mnemonic **C**). On macOS the order is Cancel, then Next; elsewhere Next, Cancel.

**Page image scaling.** Start from the 75-DPI image size; while it exceeds the 466×400 container, multiply both
dimensions by 0.9 (rounding each time). `aspectRatio = scaledW / imageW`, displayed scale `%2 = round(100 ×
aspectRatio)`; final size recomputed as `round(imageW × aspectRatio)`, `round(imageH × aspectRatio)`; smooth scaling.
`pdfRatio` (PDF points per screen pixel): if both the rendered image and the PDF page size are portrait
(`w <= h`) → `pdfPageHeight / displayedHeight`, otherwise ("rotated") → `pdfPageWidth / displayedWidth`.

**Rubber-band selection (`PageLabel`).** Mouse press: clear the four fields and the selection, remember the point.
Drag: selection = rectangle spanned by press point and current point; repaint. Release: if press and release share an
X or a Y → clear; else clamp both points into `[0,width]×[0,height]` and set the fields. Painting: the whole page is
overlaid with white at alpha 128 except the selection, which is filled blue at alpha 0.3.

**Coordinate conversions (exact, including quirks):**

* Release → fields: `field = round(pixelValue / pdfRatio)` for X, Y (top-left origin), width, height.
  *Quirk:* this divides by the ratio instead of multiplying, so the numbers displayed are **not PDF points** (they are
  pixels ÷ ratio, roughly ½ of the pixel value for A4). The values round-trip correctly because of the inverse below.
* Fields → selection (on every edit, `updateArea`): `rect_px = (int)(field × pdfRatio)` for each of x, y, w, h; if
  `w_px>0 && h_px>0` the rectangle is shown and converted, else the selection/params are cleared. "Siguiente" is enabled
  iff a rectangle exists.
* Selection → PDF (`toPdfPosition`), with `H = displayed page height`, `W = displayed width`, `s = pdfRatio`,
  `dim = pdfPageSizes[current−1]` if current page = 1 else `pdfPageSizes[current−2]` (*quirk: off-by-one, uses the
  previous page's size*):
  1. if `x > dim.width || y > dim.height` → null (no params);
  2. clamp `w` to `dim.width − x`, `h` to `dim.height − y` (*quirk: compares pixels with points*);
  3. `areaH = (y + h > H) ? H − y : h`, `areaW = (x + w > W) ? W − x : w`;
  4. emit `signaturePositionOnPageLowerLeftX = round(x × s)`, `signaturePositionOnPageLowerLeftY = round((H − y −
     areaH) × s)`, `signaturePositionOnPageUpperRightX = round((x + areaW) × s)`,
     `signaturePositionOnPageUpperRightY = round((H − y) × s)` (PDF user space, bottom-left origin, integers).

  Recommended Rust behaviour: show and accept **PDF points** in the fields, use the current page's size, convert with
  `pt = px × pdfRatio` and `y_pdf = pageHeight_pt − y_top_pt − h_pt`.

**Navigation.** `<<` → page 1; `<` / `>` → ±1 (after the first click, the next needed page is pre-rendered:
`necessary = target−2` when going back, `target+1` when going forward, ignored if outside the document); `>>` → last
page. Keyboard: Left/Right arrow (only when focus is not in a text field) = previous/next; Esc = cancel. Changing page
clears the four fields. Button enabling: single-page doc → all disabled except `>` which stays enabled when the PDF is
**not already signed** (to allow appending a page); on page 1 → `<<`,`<` disabled; on last page → `>>` disabled and `>`
enabled only if the PDF is not signed.

**Append blank page.** Pressing `>` (or Right) on the last page of an unsigned PDF asks (Yes/No, warning)
`SignPdfUiPanel.11` "¿Desea añadir una página en blanco al final del documento para firmar?" titled `SignPdfUiPanel.10`
"Añadir página". Yes → show a white page of the **first page's** size as page `n+1` (`>` disabled); No → stay.

**"Siguiente" handling** (builds properties starting from the initial ones, i.e. possibly `ownerPassword`):

* "Todas las páginas" → `signaturePages=all`;
* "Selección de páginas" → validate with `PdfUtil.checkPagesRangeInputFormat` (below); invalid → error
  `SignPdfUiPanel.26` "Error en el formato indicado en la selección de páginas. Por favor, introduzca uno correcto."
  (title `SimpleAfirma.7` "Error") and stay; valid → `signaturePages=<text as typed>`;
* "Página actual" → `signaturePages=<current page number>`;
* if the current page is the appended blank page (`current > n`): append `",append"` to the value (e.g. `"5,append"`,
  `"all,append"`);
* add the four `signaturePositionOnPage*` values;
* build the preview fragment (below) and go to the next panel.

Page-range syntax accepted by the validator (`checkPagesRangeInputFormat`): non-empty; only characters `0-9`, `-`, `,`;
must not end with `,`; no `,,`; no `---`; no element (split by `,`) that ends with `-`, starts with `--`, or is just `-`.
Semantics (implemented by the signer, `PdfUtil.getPagesRange`): comma-separated items; an item is a page number or a
range `a-b`; negative numbers count from the end (`-1` = last page; `-3--1` = last three); numbers ≤0 after
normalisation become page 1, numbers > n become n; ranges with end < start are an error; duplicates ignored.

**Preview fragment** (input image for the appearance editor): take the first item of `signaturePages`: `append` → the
blank page; `all` → page 1; otherwise the first page of the range (invalid → page 1; if not rendered, render it now).
Draw that page bilinearly scaled to exactly `pageWidth_pt × pageHeight_pt` pixels (of the page index computed, i.e.
1 pt = 1 px), then crop the rectangle `x = llx`, `y = pageHeight − ury`, `w = max(urx − 4 − llx, 1)`, `h = max(ury −
lly, 1)` (all clamped ≥0; the `−4` is a quirk).

### 3.6 Appearance editor (`SignPdfUiPanelPreview`)

Shown only when `customAppearance` is true (always in GUI mode). Layout (preferred 470×720):

1. Titled border `SignPdfUiPreview.0` "**Vista Previa**": preview label 475×200 (tooltip `SignPdfUiPreview.26`
   "Arrastre una imágen a este área para seleccionarlo y poder previsualizarlo", hand cursor). Below it, an HTML hint
   `SignPdfUiPreview.4`: "La previsualización puede diferir del resultado final. Consulte la [página de
   ayuda](https://github.com/ctt-gob-es/clienteafirma/wiki/Help-desktop-visible-pdf) para conocer las palabras clave
   para introducir información del certificado." (link opens the system browser; failure → error `SignResultPanel.0` +
   URL).
   * Left click on the preview → choose image file. Right click → popup with `SignPdfUiPreview.27` "Quitar imagen" (if
     an image is loaded) or `SignPdfUiPreview.28` "Añadir imagen".
   * Drag & drop onto the preview panel: accepts a file list; >1 file → warning `SignPanel.18` (title
     `SimpleAfirma.48` "Advertencia"; *quirk:* this key is missing from the bundles, so the text shows as
     `!SignPanel.18!` – intended meaning "only one file can be used") and uses the first; `http://`, `https://`, `ftp://` → error `SignPanel.24` "No se
     soporta la firma de ficheros remotos con esta aplicación, seleccione un fichero local para firmarlo"; `file://` URIs
     are converted to paths.
2. Titled border `SignPdfUiPreview.1` "**Configuración de firma**":
   * `SignPdfUiPreview.37` "Imagen de firma:" + read-only path field + button `SignPdfUiPreview.38` "Examinar" (a11y
     `.39` "Cargar imagen de firma") + button `SignPdfUiPreview.40` "Limpiar" (a11y `.41` "No usar imagen").
   * `SignPdfUiPreview.36` "Texto de la firma:" + multi-line text area (4 rows × 60 cols, white background, word-wrap,
     min 400×90, no horizontal scroll; **Tab / Shift+Tab move focus** instead of inserting tabs). Initial text =
     pref `pdfLayer2Text` (default "Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido
     por $$ISSUERCN$$").
   * Font row: font-family combo (each item rendered in its own font, 14 pt; tooltip `SignPdfUiPreview.20` "Tipo de
     letra"), size spinner (1–50, step 1, initial 12, invalid input rejected; tooltip `.18` "Tamaño del texto"), rotation
     combo (tooltip `.42` "Rotación del texto").
   * Style row: four toggle buttons `N` (bold, `.14` "Negrita"), `K` (italic, `.15` "Cursiva"), `S` (underline, `.16`
     "Subrayado"), `T` (strikethrough, `.17` "Tachado") rendered with HTML `<b>/<i>/<u>/<s>`, plus a colour combo
     (swatch + name, max 3 visible rows; tooltip `.19` "Color texto").
3. Checkbox `SignPdfUiPreview.33` "**Recordar configuración**" (checked by default).
4. Buttons: `SignPdfUiPreview.31` "Restaurar configuración" (mnemonic **R**), `SignPdfUiPreview.5` "Aceptar" (mnemonic
   **A**), `SignPdfUiPreview.6` "Cancelar" (mnemonic **C**). Order: Restore, OK, Cancel (macOS: Restore, Cancel, OK).

Option tables (index = value emitted):

| Font combo order | Name | `layer2FontFamily` | Font file bundled in afirma-crypto-pdf |
|---|---|---|---|
| 1 | Courier | `0` | `/fonts/courier.ttf` |
| 2 | Helvetica | `1` | `/fonts/helvetica.ttf` |
| 3 | Times Roman | `2` | `/fonts/times.ttf` |

(The signer also accepts 3 = Symbol, 4 = ZapfDingBats, not offered in the UI. If a system font with the same name exists
it is used for the preview, otherwise the bundled TTF is registered.)

| Colour item | Label (`ColorResource.N`) | RGB used in preview | `layer2FontColor` |
|---|---|---|---|
| 0 | Negro | 0,0,0 | `black` |
| 1 | Blanco | 255,255,255 | `white` |
| 2 | Gris claro | **128,128,128** | `lightGray` |
| 3 | Gris | **192,192,192** | `gray` |
| 4 | Gris oscuro | 64,64,64 | `darkGray` |
| 5 | Rojo | 255,0,0 | `red` |
| 6 | Rosa | 255,175,175 | `pink` |

*Quirk:* the preview RGB values for "Gris claro" and "Gris" are swapped relative to their names.

| Style toggles | `layer2FontStyle` |
|---|---|
| none | `0` |
| bold | `1` |
| italic | `2` |
| bold + italic | `3` |
| underline | `4` |
| strikethrough | `8` |

Mutual exclusion rules: selecting bold or italic deselects underline and strikethrough; selecting underline deselects
bold, italic, strikethrough; selecting strikethrough deselects bold, italic, underline. So only the combinations above
are reachable (the signer would accept OR-combinations).

| Rotation item | Label (`RotationModel.N`) | `signatureRotation` |
|---|---|---|
| 0 | No rotar | (not emitted) |
| 1 | Rotar 90º | `90` |
| 2 | Rotar 180º | `180` |
| 3 | Rotar 270º | `270` |

**Image (rubric) loading** (`loadRubricFile`): validation errors (title `SimpleAfirma.7` "Error"): not exists →
`SignPanel.3`; directory → `SignPanel.21`; not readable → `SignPanel.7`; empty → `SignPanel.5`; name not ending in
`jpg|jpeg|png|gif|bmp` (case-sensitive `endsWith`) → `SignPanel.101` "El archivo no es un formato de imágen valido".
The file chooser (generic open dialog, §3.13.4) uses title `SignPdfUiPreview.21` "Seleccione el fichero para cargar la
imagen", filter `SignPdfUiPreview.22` "Archivos de imagen (.jpg, .jpeg, .gif, .png, .bmp)", starting in the directory
of the current image. Decode failure → error `SignPdfUiPreview.24` "No se ha podido cargar la imagen seleccionada.
Proporcione una imagen en formato JPEG." titled `.23` "Error cargando imagen". If the image has an alpha channel or any
fully transparent pixel, show warning `SignPdfDialog.9` "No se soporta el uso de imagenes con transparencias. La
previsualización no refleja el acabado final de la firma." (title `SignPdfDialog.8` "Advertencia").

**Preview rendering** (re-run on every change):

1. Base image = the fragment from §3.5. If larger than 475×200, shrink by repeated ×0.9 until it fits; `scale =
   originalWidth / newWidth` using **integer division** (quirk). If `signaturePage` equals `append` the base is replaced
   by a white image (never true in practice because the area panel sets `signaturePages`).
2. If an image is loaded: rotate it by the opposite angle (90 → rotate 270°, 270 → rotate 90°, 180 → 180°; width/height
   swapped for 90/270), scale it uniformly to fit the base (`min(baseW/imgW, baseH/imgH)`), centre it, draw it over the
   base.
3. Draw the text in the selected colour with antialiasing, font size `max(1, round(size / scale) − 3)`: split by `\n`;
   each line that is wider than the available width is word-wrapped (greedy on whitespace); lines drawn from the top with
   a 4 px left margin, advancing one font height per line. Rotation: 0 → width = imageW; 90 → rotate −π/2, width =
   imageH; 180 → rotate π; 270 → rotate π/2, width = imageH. Placeholders such as `$$SUBJECTCN$$` are drawn
   **literally** in the preview (no substitution).

**"Aceptar"** emits (adds to the properties received from the area panel):

* `layer2Text` = trimmed text (always present, possibly empty);
* only if the text is non-empty: `layer2FontFamily`, `layer2FontSize` (spinner value), `layer2FontStyle`,
  `layer2FontColor` (tables above);
* `signatureRotation` if ≠ 0;
* if the image path is non-empty: re-read the file; `signatureRubricImage` = standard Base64 (no line breaks) of the
  **raw file bytes** (PNG/GIF/BMP are passed as-is even though the signer documentation says JPEG); read error → error
  dialog and stay on the panel;
* if "Recordar configuración" is checked, persist (and `flush`) prefs: `pdfLayer2Text` ← text; if text non-empty also
  `pdfLayer2FontFamily`, `pdfLayer2FontSize`, `pdfLayer2FontStyle`, `pdfLayer2FontColor`; `pdfSignatureRotation` ← rotation
  only if non-zero (*quirk: choosing "No rotar" never resets a previously saved rotation*); `pdfSignatureImage` ← image
  **path** if an image was used, else the key is removed.

**Initial values** (`loadProperties`) come from those prefs (§4 defaults: text as above, family `0`, size `12`, style
`0`, colour `black`, rotation `0`, image empty). If `pdfSignatureImage` points to a loadable image, it is preloaded.
**"Restaurar configuración"** reloads the same fields from the *default* preference source
(`PreferencesManager.get(key, PreferencesSource.DEFAULT)`, i.e. the packaged/administrator defaults, see §4).
*Quirk:* styles are applied by "clicking" toggles without first clearing the current ones, so restoring may toggle a
style off instead of on.

**Keyboard shortcuts** (any focused control of the panel): Esc = cancel; Ctrl+N bold; Ctrl+K italic; Ctrl+S underline;
Ctrl+T strikethrough; Ctrl+P = open image chooser. Initial focus: font combo.

**Placeholders** available in `layer2Text` (expanded by the PAdES signer, listed in `PdfExtraParams` docs):
`$$SUBJECTCN$$`, `$$SUBJECTDN$$`, `$$ISSUERCN$$`, `$$CERTSERIAL$$`, `$$SIGNDATE=<SimpleDateFormat pattern>$$`,
`$$GIVENNAME$$`, `$$SURNAME$$`, `$$ORGANIZATION$$`, `$$PSEUDONYM$$`, `$$OU$$`, `$$OUS$$`, `$$TITLE$$`, `$$REASON$$`,
`$$LOCATION$$`, `$$CONTACT$$` (the last three come from the PAdES preferences `padesSignReason`,
`padesSignProductionCity`, `padesSignerContact`). Expansion rules are in the PAdES spec.

### 3.7 Visible stamp (image mark) panel (`SignPdfUiPanelStamp`)

Purpose: place an arbitrary image ("marca visible") on one page or all pages, independent of the signature
appearance. Layout (preferred 470×630, dialog height `min(860, 0.9·screenH)`):

1. Top row: button `SignPdfUiStamp.18` "Seleccionar imagen" + read-only path field.
2. Titled border `SignPdfUiStamp.2` "**Posición de marca**": message `SignPdfUiStamp.26` "Inserte o seleccione el área
   para la imagen de marca visible."; X/Y/Anchura/Altura fields (same digit filter); page preview 466×410; pagination
   `<< < "Página %0 de %1 (escala: %2%)" > >>` (`SignPdfUiStamp.6`); checkbox `SignPdfUiStamp.7` "Incluir imagen en todas
   las páginas." (when checked, all four navigation buttons are disabled).
3. Buttons "Aceptar" (`SignPdfUiStamp.8`, mnemonic A) / "Cancelar" (`SignPdfUiStamp.10`, mnemonic C), macOS order
   swapped.

Behaviour: same rubber band / field conversion as §3.5 except that `toPdfPosition` uses the **current** page size (no
off-by-one) and there is no page appending and no page-range field. Image chooser: title `SignPdfUiPreview.21`,
extensions `jpg, jpeg, png, gif, bmp`, description `SignPdfUiPreview.43`; the file is decoded to validate it, then
`image=<Base64 of raw file bytes>` is stored immediately (decode failure → `SignPdfUiPreview.24` error). "Aceptar" is
enabled only when both an area and an image exist. On Aceptar it adds: `imagePage = "0"` (all pages) or the current page
number; `imagePositionOnPageLowerLeftX/Y`, `imagePositionOnPageUpperRightX/Y` (same formulas as §3.5 with prefix
`image`). Keyboard: Left/Right page navigation (even inside text fields), Esc cancel. Navigation errors:
`SignPdfUiStamp.15` / title `SignPdfUiStamp.12`. *Quirk:* the pre-render call uses the current page instead of the
needed one.

### 3.8 Extra-params produced by the visible-signature UI (reference)

| Key (exact) | Value | Produced by |
|---|---|---|
| `signatureField` | Name of an existing blank signature field | §3.2 (GUI only) |
| `signaturePages` | `all` \| page range text (e.g. `1-3,-1`) \| current page number; optionally suffixed `,append` | §3.5 |
| `signaturePage` | Page of an existing field (only from the unused full field dialog) | §3.2 dead code |
| `signaturePositionOnPageLowerLeftX` / `…LowerLeftY` / `…UpperRightX` / `…UpperRightY` | Integer PDF user-space coordinates | §3.5 |
| `layer2Text` | Text with `$$…$$` placeholders (may be empty) | §3.6 |
| `layer2FontFamily` | `0`/`1`/`2` | §3.6 (if text non-empty) |
| `layer2FontSize` | `1`…`50` | §3.6 (if text non-empty) |
| `layer2FontStyle` | `0`,`1`,`2`,`3`,`4`,`8` | §3.6 (if text non-empty) |
| `layer2FontColor` | `black`,`white`,`lightGray`,`gray`,`darkGray`,`red`,`pink` | §3.6 (if text non-empty) |
| `signatureRotation` | `90`,`180`,`270` | §3.6 (if ≠ 0) |
| `signatureRubricImage` | Base64 of the image file | §3.6 |
| `image` | Base64 of the stamp image file | §3.7 |
| `imagePage` | `0` (= all pages) or page number | §3.7 |
| `imagePositionOnPageLowerLeftX` / `…LowerLeftY` / `…UpperRightX` / `…UpperRightY` | Integer PDF coordinates | §3.7 |
| `ownerPassword` | Password typed to open the PDF | §3.3 |
| `certificationLevel` | `1`,`2`,`3` (never `0`) | SignPanel (§3.1.1) |

### 3.9 Protocol-mode differences (afirma://)

* No empty-field chooser, no stamp panel; dialog has no parent and is shown blocking (`dialog.setVisible(true)`).
* `customAppearance` only when the web page sends `visibleAppearance=custom`; otherwise only the area panel is shown.
* The listener copies into the request extra-params: the four `signaturePositionOnPage*`; `signaturePage` if present
  else `signaturePages`; and, when present, `layer2Text`, `layer2FontFamily`, `layer2FontSize`, `signatureRotation`,
  `layer2FontStyle`, `layer2FontColor`, `signatureRubricImage`. (`ownerPassword` is **not** copied.)
* Cancel: sets a static flag `showRubricIsCanceled`; afterwards, if `visibleSignature=want` and the request did not
  already contain the four position params **and** `signaturePage`/`signaturePages`, the operation fails with
  `VisibleSignatureMandatoryException` ("Es obligatorio mostrar la firma en el documento PDF", returned to the page as a
  cancellation/error per the protocol spec). With `optional`, cancel = sign without visible signature (or with the
  position already supplied by the page). *Quirk:* the static flag is never reset within the process.

### 3.10 Keystores: identifiers, defaults and selection rules

#### 3.10.1 Keystore types and their persisted names

Keystores are identified in preferences by the `AOKeyStore` **display name** (exact strings, Spanish, not
translated). Pref `defaultKeystore` stores one of these names or `default`.

| Enum | Name string (persisted) | Provider | Store password callback | Notes |
|---|---|---|---|---|
| `WINDOWS` | `Windows` | `Windows-MY` | dummy | CurrentUser\My via CAPI/CNG |
| `APPLE` | `Llavero de Mac` | `KeychainStore` | dummy | macOS login keychain |
| `SHARED_NSS` | `NSS` | `PKCS11` | prompt `AOKeyStore.13` | Linux system NSS DB (`~/.pki/nssdb`) |
| `PKCS12` | `PKCS#12 / PFX` | `PKCS12` | prompt `AOKeyStore.1` "Introduzca la contraseña del almacén PKCS#12." | file path in pref `defaultLocalKeystorePath` |
| `JAVA` / `JAVACE` / `JCEKS` | `Java KeyStore / JKS`, `Java KeyStore / JKS (Case Exact)`, `Java Cryptography Extension KeyStore (JCEKS)` | | prompts | not offered in AutoFirma UI |
| `PKCS11` | `PKCS#11` (**name is mutated at runtime** to the registered smart-card name) | `PKCS11` | prompt `AOKeyStore.4` | lib path from pref / registration |
| `SINGLE` | `PKCS#7 / X.509` | | | unused here |
| `MOZ_UNI` | `Mozilla / Firefox (unificado)` | `PKCS11` | prompt `AOKeyStore.5` | Firefox profile NSS + PKCS#11 modules |
| `MOZ_UNI_WITH_OS` | `Mozilla / Firefox (unificado) junto a almacen de SO` | `PKCS11` | prompt `AOKeyStore.5` | Firefox + OS store, used when invoked from a browser |
| `TEMD` | `TEMD (Tarjeta del Ministerio de Defensa)` | | | |
| `WINADDRESSBOOK`, `WINCA` | `Windows / Internet Explorer (otras personas / libreta de direcciones)`, `Windows / Internet Explorer (CA intermedias)` | `Windows-ADDRESSBOOK`, `Windows-ROOT` | | |
| `CERES`, `CERES_430` | `Tarjeta FNMT-RCM CERES`, `Tarjeta FNMT-RCM CERES 4.30 o superior` | | | JMulticard |
| `DNIEJAVA` | `DNIe y tarjetas FNMT-TIF` | `DNI` | (PIN asked at signing) | JMulticard 100 % Java driver |
| `KNOWN_SMARTCARDS`, `SMARTCAFE` | … | | | |

*Gotcha:* the Java enum is a global singleton and `PKCS11.setName(...)` mutates it; model keystore descriptors as values
in Rust.

OS default (`AOKeyStore.getDefaultKeyStoreTypeByOs`): Windows → `WINDOWS`; macOS → `APPLE`; Linux → `SHARED_NSS`;
Solaris → `MOZ_UNI`; anything else → none. "System keystore" when switching from the dialog: Windows → `WINDOWS`,
Linux/Solaris → `SHARED_NSS`, macOS → `APPLE`.

#### 3.10.2 Resolving a name (`SimpleKeyStoreManager.getKeyStore(name, invokedFromBrowser)`)

1. null → none.
2. Case-insensitive match of `name.trim()` against every enum **name string**; if `invokedFromBrowser` and the match is
   `MOZ_UNI`, return `MOZ_UNI_WITH_OS`.
3. Else if `name` is a registered smart card (user or system registrations, §3.10.6) → `PKCS11` renamed to `name`.
4. Else try the enum **constant identifier** (`valueOf`, e.g. `WINDOWS`, `MOZ_UNI`; same Firefox+OS rule).
5. Else log "Almacen de claves no reconocido" → none.

`getDefaultKeyStoreType()` (desktop GUI): read pref `defaultKeystore`; if absent or `default` → OS default. Otherwise
resolve and sanitise: `MOZ_UNI` only if Firefox is available (a Mozilla profile directory **and** an NSS library
directory can be found) else OS default; `WINDOWS` only on Windows; `APPLE` only on macOS; unresolved name → OS default.

#### 3.10.3 Desktop GUI startup loading

* If the DNIe start screen applies (no file argument, pref `hideDnieStartScreen=false` and at least one PC/SC reader
  present) the DNIe wait panel is shown first (§2); "use DNIe" loads `DNIEJAVA` (`forced` = a store was preloaded),
  "skip" loads the default store.
* Linux (any OS other than Windows/macOS): before building the GUI the app configures JMulticard (below) and tries an
  **early preload of `MOZ_UNI`** (description `AFIRMA-NSS-KEYSTORE`, no password callback) because NSS cannot be
  initialised later in the process (CKR_DEVICE_ERROR). Failure is only logged. If later the default store is `default`
  and a store was preloaded, the concurrent load is skipped; otherwise the preloaded store is discarded.
* `loadDefaultKeyStore()` runs `SimpleKeyStoreManagerWorker` in the background (wait cursor), which calls
  `SimpleKeyStoreManager.getKeyStore(dnie, forced, parent)` and on success stores the manager in the app.

`SimpleKeyStoreManager.getKeyStore(dnie, forced, parent)`:

```
if dnie:
    enable JMulticard; try load DNIEJAVA
      SmartCardLockedException → warning SimpleKeyStoreManager.9 "Su DNIe está bloqueado, debe acudir a una comisaría…" (title .10)
      CardNotPresentException → Yes/No ".1 No se ha detectado un DNIe insertado ¿Desea reintentar?" (title .2) → retry
      InvalidCardException → Yes/No ".3 La tarjeta detectada en el lector no es un DNIe. ¿Desea reintentar?" (title .4) → retry
      BurnedDnieCardException → warning ".5 Su DNIe está dañado…" (title .6)
      other → error ".7 No ha sido posible inicializar su DNIe. Se continuará con el almacén por defecto del sistema." (title .8)
    (the exception class is taken from the 3rd-level cause)
    if forced: throw NoDnieFoundException  (worker then keeps the previously loaded store)
configure JMulticard from pref enabledJmulticard
aoks = getDefaultKeyStoreType(); lib = defaultLocalKeystorePath if aoks is PKCS12 or PKCS11
try load(aoks, lib)
  wrong password (IOException whose cause.cause is UnrecoverableKeyException):
       message ".12 Contraseña incorrecta" and retry in a loop;
       cancel in the loop → warning ".13 Operación cancelada. Se cargará el almacén de claves del sistema." → load OS default
       other error in the loop → error ".11 No se ha podido obtener el almacén de claves por defecto: %0 . Se cargará el del sistema." → OS default
  other IOException / Exception → error .11 → load OS default
  cancel → warning .13 → load OS default
OS default failure → AOKeyStoreManagerException("No se ha podido inicializar el almacen del sistema")
```

Lazy access `SimpleAfirma.getAOKeyStoreManager()` (used when signing): if no store is loaded, load
`getDefaultKeyStoreType()` (with lib for PKCS#12/#11); on `KeystoreAlternativeException` → error `SimpleAfirma.54`
"Error al seleccionar el almacén configurado. Se cargará el del sistema."; on IOException or cancel → `SimpleAfirma.56`
"Error al leer almacén. Se cargará el del sistema."; then fall back to the OS default (failure → `SimpleAfirma.6` "No se
ha podido inicializar el almacén de claves. No podrá realizar firmas electrónicas."). If a store is loaded but the
**last keystore selected in the certificate dialog** (in-memory, §3.10.5) differs by name, the app reloads that one
(lib = last selected lib for PKCS#12/#11), with the same fallbacks (cancel → `SimpleAfirma.57`).

#### 3.10.4 JMulticard (internal Java smart-card driver) toggle

`JMulticardUtilities.configureJMulticard(enable)`: `true` → clear JVM properties
`es.gob.afirma.keystores.mozilla.disableDnieNativeDriver` and `es.gob.afirma.keystores.mozilla.disableCeresNativeDriver`;
`false` → set both to `true`. (Despite the "native" wording, these disable the **internal** DNIe/CERES Java drivers so
that OS PKCS#11/CSP drivers are used.) Environment variables `AFIRMA_NSS_DISABLE_DNIE_NATIVE_DRIVER` /
`AFIRMA_NSS_DISABLE_CERES_NATIVE_DRIVER` (`true`) force-disable them; `isJMulticardConfigurateBySystem()` is true if
either variable is **defined** (used by the preferences UI to lock the option, §4). Pref: `enabledJmulticard`
(default `true`).

#### 3.10.5 Protocol (browser) keystore choice and background preload

Order of precedence, identical in `LoadKeystoreTask` (preload started early by `ProtocolInvocationLauncher.initLoadKeyStoreTask`)
and in the sign/batch/selectcert launchers:

1. Last keystore chosen in the certificate dialog during this process (`KeyStorePreferencesManager.lastSelectedKeystore`,
   **memory only**, never persisted) → `getValidKeyStoreType(name)`.
2. Else if pref `useDefaultStoreInBrowserCalls` is true and `defaultKeystore` ≠ `default` → `getKeyStore(name,
   invokedFromBrowser=true)` (the preload task additionally skips `PKCS#12 / PFX` and `PKCS#11`, which need a path). In
   the launchers, the lib is then pref `defaultLocalKeystorePath` for PKCS#12/#11.
3. Else (launchers only) the keystore requested by the web page (`options.getDefaultKeyStore()`, lib from the request).
4. Else the OS default. The preload task also forces the OS default when the result is not an "OS keystore"
   (`WINDOWS`, `APPLE`, `SHARED_NSS`, `MOZ_UNI`).

The preload thread loads with the store's password callback and no parent; a launcher reuses the preloaded manager
(after `join()`) only if it is the same keystore and loaded without error. In protocol mode a borderless "loading"
dialog `ProgressInfoDialog.2` "Cargando almacenes de claves" may be shown (unless `headless=true`; see §3.13.7).

#### 3.10.6 Registered PKCS#11 smart cards (`KeyStorePreferencesManager`)

java.util.prefs storage (platform mapping in §4):

* User registrations: node `/es/gob/afirma/core/keystores` (user root). Each card is a child node named `1`, `2`, … (first
  free integer) containing a single key = card display name, value = PKCS#11 library path.
* System (administrator) registrations: system root node `/es/gob/afirma/core/keystores`, same layout. If the user-root
  node `/es/gob/afirma/core/systemkeystores` exists **and** system pref `/es/gob/afirma/standalone/ui/internalpreferences`
  key `allowUpdateConfig` is true (remote config updates, §4/§9), that user-root node is used instead. When writing system
  registrations without permission, the code falls back to that user-root node.
* Adding a card: rejected silently if its library path is already registered (user or system); name collisions are
  resolved by appending `-1`, `-2`, …
* Registered cards appear in the preferences keystore combo and in the certificate dialog's "change keystore" menu (user
  cards first, then system cards).

### 3.11 Certificate selection

#### 3.11.1 Invocation and parameters

The signing code builds an `AOKeyStoreDialog` (afirma-core-keystores) around the current keystore manager and calls
`show()`, which (unless auto-selected) invokes `AOUIFactory.showCertificateSelectionDialog` → the Swing
`CertificateSelectionDialog` (afirma-ui-core-jse-keystores, loaded by reflection).

| Parameter | Desktop GUI (`SignPanelSignTask.getPrivateKeyEntry`) | Protocol launchers |
|---|---|---|
| parent | main window | none |
| checkPrivateKeys | true (only entries with a private key) | true |
| showExpiredCertificates | pref `showExpiredCerts` (default false) | **always true** |
| checkValidity | true | true |
| filters | from prefs (below) | from request `filter`/`filters` params (`CertFilterManager`, protocol spec) |
| mandatoryCertificate | false (true when re-selecting after a PIN error) | request `mandatoryCertSelection` |
| invocationFromBrowser | false | true (Firefox switch loads `MOZ_UNI_WITH_OS`) |
| allowOpenExternalStores | true | false if request filter `disableopeningexternalstores` |
| lib name in title | – | lib file name for PKCS#11/#12 |

Desktop filters (`SignPanel.getCertFilters`, combined with AND when more than one):

| Pref (default) | Filter | Effect |
|---|---|---|
| `useOnlySignatureCertificates` (false) | `KeyUsageFilter(SIGN_CERT_USAGE)` | keep certs with **nonRepudiation** key-usage bit set |
| `skipAuthCertDnie` (true) | `SkipAuthDNIeFilter` | hide certs matching LDAP filter `(&(cn=AC DNIE *)(ou=DNIE)(o=DIRECCION GENERAL DE LA POLICIA)(c=ES))` on the **issuer** with digitalSignature usage (DNIe authentication cert) |
| `useOnlyAliasCertificates` (false) | `PseudonymFilter("only")` | keep only pseudonym certificates |

Entry listing (keystore layer, see keystores spec): aliases → filtered by private-key presence, expiry (unless shown)
and filters → "friendly name" per alias (normally subject CN) → sorted case-insensitively by friendly name.

Auto-selection: if `mandatoryCertificate` and exactly one certificate remains, it is returned without showing UI.
No certificates → (dialog still shows the "no certificates" message; on close) `CertificatesNotFoundException` →
desktop error `SignPanel.29` "El almacén no contiene ningún certificado que se pueda usar para firmar." User cancel →
operation silently aborted. Other errors → `SignPanel.56` "Se encontró un error durante la operación con el certificado
seleccionado."

Post-selection validity check (`AOKeyStoreDialog.getKeyEntry`, used by callers that obtain the key through the dialog
object): if the certificate is expired / not yet valid / unverifiable, ask Yes/No with `AOKeyStoreDialog.2` ("Puede que
el certificado haya caducado. Se ha usado la hora local de su ordenador…¿Desea continuar con la operación?"), `.3`
(not yet valid) or `.4`, title `.5` "Advertencia"; No → cancelled. *Quirk:* the desktop GUI and protocol launchers fetch
the key via `context.getKeyStoreManager().getKeyEntry(alias)` and therefore **skip** this warning.

PIN error recovery (desktop): on `PinException` the keystore is refreshed and the dialog is reopened with an
`EncodedCertificateFilter(base64(cert))` and `mandatoryCertificate=true`, which auto-selects the same certificate and
re-signs; `AOCancelledSMOperationException` → refresh keystore and abort; `LockedKeyStoreException` → refresh and error
(see §2).

#### 3.11.2 Dialog layout and behaviour (`CertificateSelectionDialog` / `CertificateSelectionPanel`)

* Window: JOptionPane-based modal dialog, white background, **always-on-top** (desktop JSE manager: `alwaysOnTop=true`;
  macOS AWT manager: false and then the app re-activates itself with AppleScript `tell me to activate`). Title
  `CertificateSelectionDialog.0` = "Diálogo de seguridad del almacén %0" (keystore name) + `" : " + libName` when a
  library name is known. Height clipped to the screen height. Buttons: Aceptar/Cancelar (OK_CANCEL; only "Aceptar" when
  `disableCertificateSelection`).
* Header row: title `CertificateSelectionPanel.0` "Seleccione un certificado" (Verdana bold 14, colour `#0033BC`, white
  in high contrast) followed by icon buttons (18 px, black/white variants for Windows high contrast, which is detected via
  desktop property `win.highContrast.on`):
  1. Refresh (`ic_autorenew`, tooltip `UtilToolBar.1` "Recargar la lista de certificados") → `ksdm.refresh()` then rebuild
     the list (also **F5**).
  2. Change keystore (`ic_open_in_browser`, tooltip `UtilToolBar.2` "Cambiar almacén de claves"), only if external stores
     are allowed: dropdown menu with, depending on `getAvailablesKeyStores()`:
     `CertificateSelectionPanel.35` "Almacén de claves del sistema" (id 1), `.36` "Almacén de claves de Mozilla Firefox"
     (id 2), `.37` "Almacén de claves en fichero (PFX/PKCS#12)" (id 3), `.38` "DNI electrónico" (id 4), then one entry per
     registered smart card (id 5, label = card name). Availability: Windows/macOS → 1,2,3,4; Linux → `1,3,4` if the
     current store is `SHARED_NSS` else `2,3,4` (NSS cannot switch between system DB and Firefox profile in one process).
  3. Help (`ic_help`, tooltip `UtilToolBar.3` "Ayuda", also **F1**) → opens
     `https://github.com/ctt-gob-es/clienteafirma/wiki/Help-desktop-select-certs-<lang>-<COUNTRY>` (base URL from
     `resources/selectiondialogutil.properties` key `helpUrl`, suffix `-` + JVM default locale, e.g. `-es-ES`).
  4. View selector (`ic_view_arrow`, tooltip `UtilToolBar.4` "Vistas de certificados"): radio menu
     `CertificateSelectionPanel.25` "Vista de certificados personales" (PERSONAL), `.26` "Vista de certificados de
     representante" (REPRESENTATIVE), `.27` "Vista de certificados de seudónimo" (PSEUDONYM).
* Message line (only when ≤1 cert): 1 cert → `CertificateSelectionPanel.1` "Confirme el certificado pulsando Aceptar. Si
  no es este el certificado que desea usar pulse Cancelar." (or caller-provided sub-headline); 0 certs → `.8` "No se han
  encontrado certificados válidos en el almacén. Inserte una tarjeta inteligente en el lector y pulse Recargar, o cargue
  un almacén externo."
* Separator, then the certificate list: single selection, each row 86 px high, list width 500 px, visible rows =
  `clamp(count, 1, 4)` (scroll beyond). First row preselected. Selected row background `#D9EAFF` with a 1 px white +
  1 px `#84ACDD` border.
* Row content by view (fonts Verdana: name bold 14, details plain 11):
  * PERSONAL: [icon] friendly name / `CertificateSelectionPanel.2` "Emisor: %0. Uso: %1." (issuer CN, key-usage text) /
    `.3` "Válido desde: %0 hasta %1" (dates `dd/MM/yyyy`) / underlined link `.5` "Haga clic aquí para ver las propiedades
    del certificado". Tooltip `.29` "Certificado emitido para %0. Estado: %1." (subject CN; `.30` "vigente" or `.31`
    "caducado o aún no válido").
  * REPRESENTATIVE: subject `O` (fallback friendly name) / `.28` "Representante: %0" (subject CN) / validity / link.
    Tooltip `.32` "Certificado de %0 emitido para %1. Estado: %2."
  * PSEUDONYM: subject `title (pseudonym)` (OIDs 2.5.4.12 / 2.5.4.65; fallback title, then friendly name) / `.33`
    "Organismo: %0. Uso: %1." (OU, fallback O) or `.2` (issuer) / validity / link. Tooltip `.34` "Certificado de %0
    perteneciente a %1. Estado: %2." when it has a title/pseudonym, else `.29`.
  * Key-usage text (`KeyUsage.toString`, `coremessages`): bits checked are nonRepudiation (=SIGN), digitalSignature
    (=AUTH), dataEncipherment (=CYPH): no KU extension → "Desconocido"; S+A+C → "Firma, autenticación y cifrado"; A+C →
    "Autenticación y cifrado"; S+A → "Firma y autenticación"; A → "Autenticación"; S → "Firma"; C → "Cifrado"; else
    "Otros". (*Quirk:* "Firma y cifrado" is unreachable due to a duplicated condition.)
* Row icon (`CertificateIconManager`): family by issuer DN (uppercase contains): `O=GENERALITAT VALENCIANA` + `OU=PKIGVA`
  → ACCV; `O=DIRECCION GENERAL DE LA POLICIA` + `OU=DNIE` → DNIe; same O + `OU=CNP` → CNP; `O=FNMT` → FNMT; else
  generic. State: expired or not yet valid → `*_e.png` (error); expiring in less than `1000·60·60·25·7` ms (**175 h ≈
  7.3 days**, a typo for 7 days) → `*_w.png` (warning); else normal. Icon descriptions are the texts
  `CertificateSelectionPanel.4/7/9/11/13/15/16–24` ("Certificado de DNIe dentro del periodo de validez", "…a punto de
  caducar", "…caducado o aún no válido", etc.).
* "View properties" link: single click within the link bounds (hand cursor on hover) opens the certificate:
  macOS → write a temp `afirma*.cer` and run `osascript -e 'do shell script "qlmanage -p <path>"'` (Quick Look); other
  OS → `Desktop.open(tempfile.cer)` (OS certificate viewer); Windows fallback `cmd /C start "Detalle del certificado"
  "<file>"`; final fallback → Save dialog (`CertificateUtils.1` "Guardar certificado", default name `certificado.cer`,
  filter `.cer` "Certificado electrónico"). Temp files are deleted on exit.
* Selection: double-click a row = Aceptar (unless selection disabled); Enter activates the default button; initial focus
  on the list. After Aceptar the selected **alias** is returned and the chosen view is persisted.
* Persistence: java.util.prefs user node `/es/gob/afirma/ui/core/jse/certificateselection`, key `certView` =
  `PERSONAL` | `REPRESENTATIVE` | `PSEUDONYM` (default PERSONAL).
* Changing keystore (`AOKeyStoreDialog.changeKeyStoreManager`): the dialog stops being always-on-top (PIN/file
  dialogs may appear), loads the new store and, on success, replaces the dialog's store, refreshes the list and title, and
  records it as "last selected keystore" (+ lib for PKCS#12/#11) for the rest of the process:
  * Firefox → `MOZ_UNI` (or `MOZ_UNI_WITH_OS` from browser); the recorded name is always `MOZ_UNI`'s.
  * PKCS#12 → open dialog title `AOKeyStoreDialog.6` "Selección de almacén local", filter `pfx, p12` described
    `AOKeyStoreDialog.7` "Almacenes de claves (*.p12, *.pfx)", then password prompt `AOKeyStore.1`; wrong password →
    `AOKeyStoreDialog.11` "Contraseña incorrecta." and re-prompt until success/cancel.
  * DNIe → `DNIEJAVA` (parent passed for PIN dialogs).
  * System → OS keystore (§3.10.1).
  * Registered card → `PKCS11` with that name and library.
  * Errors → `AOKeyStoreDialog.10` "Error al cargar el nuevo almacén de claves." titled `.9` "Error"; cancel → no change.

#### 3.11.3 Smart-card PIN dialogs (afirma-keystores-jmulticard-ui, brief)

When JMulticard handles DNIe/CERES cards, the PIN is requested at signing time with a custom accessible dialog
(`InputPasswordSmartcardDialog`): title `CommonPasswordCallback.1` "DNI Electrónico: Introducción de PIN" (or `.2`
"Tarjeta inteligente: Introducción de PIN"); prompt `.3`/`.5` "Por favor, introduzca el PIN del DNIe.\nIntentos
restantes: %0"; show/hide password eye button; paste; checkbox `InputPasswordSmartcardDialog.useCache` "Recordar
contraseña durante la sesión" (PIN cached for **1 hour**, prefs `useCacheDni` / `useCacheCeres` in user node
`/es/gob/afirma/keystores/jmulticard/ui`, default false). DNIe additionally asks for confirmation `CustomDialog.confirmDialog.prompt`
"¿Desea realizar una firma electrónica con su clave privada?" (cached with the PIN) and may ask for the CAN
(`CanPasswordCallback.0`). Exact behaviour belongs to the keystores/smart-card spec.

### 3.12 Background tasks (`ui/tasks`)

| Task | Started | Behaviour |
|---|---|---|
| `SSLContextConfigurationTask` (thread) | At every startup, after proxy configuration, before CLI/GUI dispatch (§1) | `HttpManager.setSecureConnections(pref secureConnections, default true)`; `HttpManager.setSecureDomains(pref secureDomainsList)`; if NOT (`allowPersonalTruststore` AND `allowAutoImportTrustedCerts`) set JVM property `blockAutoImportTrustedCerts=true`; if secure connections: when `allowPersonalTruststore`, install the app truststore (`~/.afirma/TrustedCertsKeystore.jks`, JKS, password `changeit`, only if it has entries) **in addition** to the JVM default trust managers as the default HTTPS socket factory; then a throw-away HTTPS request to `https://test.conexion.gob.es/` with 100 ms connect timeout (to make the new SSL context effective; errors ignored). Exceptions are stored for later inspection. |
| `CheckTrustKeyStoreTask` (SwingWorker) | Desktop GUI start (after `initGUI`) | Tries to build the local WebSocket TLS context: loads `autofirma.pfx` (PKCS#12, keystore and key password `654321`, context `TLSv1`) from the application directory, else from the alternative directory (§9). Failure → error dialog `TrustedKeyStoreError.0` "No se han encontrado las claves para la conexión segura con el navegador. Ejecute la función de restauración de la instalación desde el menú de herramientas de Autofirma para poder firmar." with error code `SimpleErrorCode.Internal.TRUSTSTORE_INCORRECT_INSTALLATION` (shown as `AFxxxx`, §3.13.6). |
| `LoadKeystoreTask` (thread) | Protocol invocations (`initLoadKeyStoreTask`) | §3.10.5 |
| `SimpleKeyStoreManagerWorker` (SwingWorker) | Desktop GUI | §3.10.3 |

### 3.13 Generic dialogs (`afirma-ui-core-jse`)

#### 3.13.1 UI manager selection

`AOUIFactory` picks the implementation once: macOS → `AWTUIManager` (native AWT `FileDialog` for open/save, extends
JSE); Android → (n/a); others → `JSEUIManager` (Swing). All dialogs force the Swing option-pane button texts to the
localised `JSEUIManager.3` "Aceptar", `.5` "Cancelar", `.99` "Sí", `.100` "No".

#### 3.13.2 Password dialog (`getPassword(text, icon, charset, beep, parent)`)

Modal option dialog titled `JSEUIManager.24` "Introduzca la contraseña"; label = given text (or the title text); one
10-column password field focused initially; optional character whitelist (characters outside it are rejected, optional
beep); OK returns the chars; Cancel/close → `AOCancelledOperationException`. Optional icon.

#### 3.13.3 Double password dialog (`getDoublePassword`)

Same title; two password fields (second label default `JSEUIManager.2` "Repita de nuevo la contraseña"); "Aceptar" is
enabled only when the first password has **length > 1** and both are equal. Close (no value) returns an **empty
array** (quirk; not a cancel); Cancel → cancelled exception. (Not used by the AutoFirma desktop flows; kept for API
parity.)

#### 3.13.4 Open-file dialog (`getLoadFiles(title, currentDir, filename, extensions[], description, selectDirectory, multiSelect, icon, parent)`)

* Swing (Windows/Linux): `JFileChooser` with localised labels ("Buscar", "Nombre de archivo", "Tipo de archivo",
  "Abrir", "Cancelar", "Nombre de carpeta"); directories-only when `selectDirectory`; one extension filter
  `(description, extensions)` when given; optional window icon; initial directory/file via the rule below. Approve →
  selected file(s) and the **current directory is remembered**; cancel → cancelled exception.
* macOS (`AWTUIManager`): native `FileDialog` (LOAD); initial directory = remembered dir when `currentDir` is null;
  multi-select supported; extension filtering via a filename filter (`name.endsWith(ext)`); directory mode sets system
  property `apple.awt.fileDialogForDirectories=true` (reset to false afterwards) and preselects `*.`; remembers the
  directory. (On Windows the AWT variant would put `*.ext` as file name because filters do not work there.)
* Remembered directory: java.util.prefs user node `/es/gob/afirma/ui/core/jse` key `currentDir` (string path).
* Initial location rule (`configureDefaultDir`): if both `currentDir` and `filename` → select `currentDir/filename`;
  else `dir = currentDir ?? remembered currentDir`; if `filename` → select `dir/filename` (or just `filename`); else if
  `dir` → set current directory.

#### 3.13.5 Save-file dialog (`saveDataToFile(data, title, currentDir, selectedFile, filters, defaultFilter, parent)`)

* Swing: `JFileChooser` save mode, accessible name `JSEUIManager.81` "Guardar Fichero" (description `.82`), button
  `.89` "Guardar". "All files" filter is kept; each `GenericFileFilter` with extensions is added; `defaultFilter` is
  preselected. When the user switches filter, the file name's extension is replaced (old first extension → new first
  extension) or the new extension appended.
* On approve: canonical path; if a specific (non-"all") extension filter is active and the name does not match it,
  append `.` + its first extension (lower case). If the file exists → Yes/No/Cancel dialog `JSEUIManager.77` "El fichero
  '%0' ya existe, ¿desea sobrescribirlo?" titled `.85` "Guardar como": Yes → overwrite, No → **reopen the chooser**,
  Cancel → cancelled exception. If `data` is non-null it is written (write error → error `JSEUIManager.88` "Error al
  almacenar el fichero de datos." and the chooser reopens); the directory is remembered; the file is returned (callers
  may pass `data=null` to just pick a path).
* macOS native `FileDialog` (SAVE): file name and directory preset (remembered dir if none); all filter extensions are
  merged into one filename filter (macOS ignores filters); **no overwrite confirmation and no extension appending** in
  this path (the native dialog asks itself); writes data if given; *quirk:* the directory is not remembered on save.

#### 3.13.6 Message / confirm / input / error dialogs

* `showConfirmDialog(parent, message, title, optionType, messageType)` → standard option pane; accessible description =
  message; closing returns CANCEL.
* `showMessageDialog(parent, message, title, type[, icon])` → standard message pane.
* `showInputDialog(...)` → standard input pane (free text, or combo of `selectionValues`).
* `showErrorMessage([parent,] message, title, type, throwable)` → `ErrorManagementDialog`: modal, non-resizable,
  **always-on-top**, packed and centred on the parent; content = icon (`error_icon.png` for ERROR, `warning_icon.png`
  for WARNING, none otherwise) + message rendered as HTML with `\n` → `<br>`, and a single button `JSEUIManager.1`
  "Cerrar". There is **no "details"/stack-trace or report button**. If the throwable is an `AOControlledException`
  carrying an error code: with a Frame parent the title becomes `"<title> AF<code>"`; with a JDialog parent the title
  becomes `"<title> - AF<code>"` and the message is prefixed `"AF<code> - "`. Without parent a dummy frame "Error"
  (900×900 at 100,20, not shown) is used as owner. Error-code catalogue: see the error-codes spec.

#### 3.13.7 Wait / progress dialogs (afirma-simple, used by these flows)

* `CommonWaitDialog(parent, message, title)`: application-modal, non-closable (DO_NOTHING_ON_CLOSE), label + indeterminate
  progress bar (macOS: circular style), app icons, centred on screen, non-resizable; `setMessage` updates the label (used
  as the sign wait dialog, see §2).
* `ProgressInfoDialog` / `ProgressInfoDialogManager`: undecorated rounded (radius 20) white window with an 18 pt label,
  centred; only for protocol invocations: shown when the `afirma://` URL parameter `dlgload` is absent or `true` and pref
  `enableProgressDialog` (default true) is true; never in the desktop app.

#### 3.13.8 Tree conversion

`JSEUtils.convertToSwingModel(AOTreeModel)` converts the core signer tree model into a UI tree (used by the signature
viewer, §2). Breadth-first copy of user objects; no other logic.

### 3.14 Accessibility in these dialogs (details in §12)

Mnemonics (A = accept/next, C = cancel, R = restore); explicit accessible names/descriptions on every control (keys
`*.1`, `*.2`, `*.4`, `.16`–`.19`, `SignPdfUiPreview.7–.13`); keyboard page navigation (arrows), Esc to cancel, Ctrl
shortcuts for text styles, F1/F5 in the certificate dialog, Tab traversal out of the text area; Windows high-contrast
detection (`win.highContrast.on` / `LookAndFeelManager.WINDOWS_HIGH_CONTRAST`) switches toolbar icons to white variants
and swaps them on focus; dialogs' accessible description = message text.

### 3.15 Gotchas summary

1. GUI: cancelling the visible-signature dialog or a preview failure still signs (invisibly). Protocol: `want` makes it
   mandatory.
2. The coordinate fields of the area/stamp panels show non-PDF units; the area panel uses the previous page's size for
   clamping on pages > 1.
3. Rubric/stamp images are passed as raw file bytes in Base64 (PNG/GIF/BMP allowed though documented as JPEG);
   transparency only triggers a warning.
4. Owner password ends up in extra-params and in the INFO log line together with the images.
5. `allowCertifiedPDF` is not consulted in multi-file mode (reads `padesVisibleSignature` instead).
6. Expiry warning icon threshold is 175 h, not 7 days.
7. The post-selection validity warning (expired cert) is effectively never shown by AutoFirma's own flows.
8. Last-selected keystore is process-memory only; persisted default is `defaultKeystore` (names table §3.10.1).
9. On Linux NSS must be initialised early (preload) and the dialog cannot switch between the system NSS DB and the
   Firefox profile.
10. The empty-field chooser's window close = "create new field"; the full field dialog is dead code.
11. Global mutable keystore enum names (`PKCS11.setName`) – avoid in Rust.


## 4. Preferences

This section specifies every persisted setting of the desktop application, how and where it is stored on each OS, the
three-layer resolution model (user / system / built-in default), the administrator "blocked preferences" mechanism, the
`.afconfig` import/export format (including signed configuration files and the remote auto-update of the system
configuration), the Preferences dialog, and how each preference is turned into signature parameters.

Main Java sources (for traceability only):
`afirma-ui-simple-configurator-common/.../configurator/common/PreferencesManager.java` (key constants, resolution,
locking helpers), `properties/preferences.properties` (built-in defaults, same module), `PreferencesPlistHandler.java`
(import/export), `ConfigUpdaterManager.java`, `ConfigDataInfo.java`, `XAdESValidator.java`, `SignatureInfo.java`,
`ConfiguratorErrorCode.java`, `xmlwise/Plist.java`; `afirma-core-prefs/.../KeyStorePreferencesManager.java` (smart-card
registry); `afirma-simple/.../ui/preferences/**` (dialog and panels); `afirma-simple/.../ui/ExtraParamsHelper.java`
(preferences -> extraParams); `ProxyUtil.java`/`ProxyConfig.java` (proxy storage); `HttpManager.java`;
`afirma-core/.../misc/http/TrustStoreManager.java` and `UrlHttpManagerImpl.java` (trusted store and secure domains).

### 4.1 Overview of the model

* There are **three layers** for every key of the main preference set:
  1. **User** value – set by the user through the GUI (or by importing an `.afconfig` file from the GUI).
  2. **System** value – set by an administrator/installer (system-wide), or downloaded automatically from a
     configuration URL (see §4.11).
  3. **Default** value – compiled into the application (`preferences.properties`, reproduced in §4.5).
* **Resolution order for reads is user → system → default** (first non-null wins). This is true for *every* key,
  including the lock flag itself (see the gotchas in §4.4.5).
* **Writes from the GUI always go to the user layer**, with a "do not shadow" rule: if the value being written equals the
  current system value (or the default when there is no system value), the user key is *deleted* instead of written,
  so that later administrator changes become visible again (§4.3.2).
* There is a separate, very small "internal" system set (configuration-file URL, auto-update flag, hash, last check
  date) that is never exported and partly cannot be overridden by users (§4.4.3).
* Registered PKCS#11 smart cards are stored in a *different* preference tree (`KeyStorePreferencesManager`, §4.15) with
  its own user/system split.
* A handful of unrelated small settings live in other nodes (last directory, certificate list view, DNIe PIN cache,
  updater last check, plug-in settings) – §4.2.1.

All values are stored as **strings**. Booleans are stored as the strings `"true"`/`"false"` (Java
`Preferences.putBoolean`); reading a boolean whose stored string is not `true`/`false` (case-insensitive) yields the
fallback of the next layer/default. Integers (font size, rotation, certification level) are stored as decimal strings.

### 4.2 Storage backend and per-OS locations

The Java application uses `java.util.prefs.Preferences`. A Rust reimplementation must (a) choose its own store but
(b) **read the legacy Java locations** for migration and, most importantly, (c) honour administrator-provided values in
the *system* locations listed below, because corporate deployments (GPO, MDM, Ansible...) already write them.

#### 4.2.1 Logical nodes

| Logical store | Root | Node path (Java absolute path) | Contents |
|---|---|---|---|
| Main user preferences | user | `/es/gob/afirma/standalone/ui/preferences` | All keys of §4.5 written by the user |
| Main system preferences | system | `/es/gob/afirma/standalone/ui/preferences` | Admin/installer values (same key names) |
| "Updated" system preferences (user-side copy) | user | `/es/gob/afirma/standalone/ui/systempreferences` | Copy of system preferences downloaded by the auto-update when the process cannot write the real system node; logically treated as *system* layer (§4.11) |
| Internal system preferences | system | `/es/gob/afirma/standalone/ui/internalpreferences` | `configFileUrl`, `allowUpdateConfig`, `configFileSHA256`, `configDate`, and the admin keys `requireSignedPrerefences`, `certHashToSignedPrerefences` (§4.4.3) |
| Internal preferences, user overlay | user | `/es/gob/afirma/standalone/ui/internalpreferences` | Fallback location for `configFileSHA256`/`configDate` when the system node is not writable; overlays every non-exclusive internal key |
| Smart cards (user) | user | `/es/gob/afirma/core/keystores/<n>` (`n` = `1`,`2`,…) | One child node per card, containing exactly one entry `<card name>` = `<PKCS#11 library path>` |
| Smart cards (system) | system | `/es/gob/afirma/core/keystores/<n>` | Same structure, admin defined |
| Smart cards ("updated" system copy) | user | `/es/gob/afirma/core/systemkeystores/<n>` | Used instead of the system node when it exists **and** `allowUpdateConfig` is `true` in the system internal node |
| Updater | user | `/es/gob/afirma/standalone` | `lastCheckDate` = `yyyyMMdd` of last update check (§8) |
| File chooser last directory | user | `/es/gob/afirma/ui/core/jse` | `currentDir` = absolute path of last directory used in open/save dialogs |
| Certificate selection view | user | `/es/gob/afirma/ui/core/jse/certificateselection` | `certView` = `PERSONAL` (default) \| `REPRESENTATIVE` \| `PSEUDONYM` (last tab of the certificate selection dialog, see §3) |
| DNIe / CERES PIN cache flag | user | `/es/gob/afirma/keystores/jmulticard/ui` | `useCacheDni`, `useCacheCeres` (booleans, default `false`) – initial/last state of the checkbox `"Recordar contraseña durante la sesión"` (`InputPasswordSmartcardDialog.useCache`) of the DNIe / CERES PIN dialog (see §3) |
| Plug-in configuration | user | Java package node of each plug-in class (e.g. `/es/gob/afirma/plugin/hash`) | Free key/value pairs defined by each plug-in (§7), e.g. hash plug-in keys `createHashAlgorithm`, `createHashFormat`, `createHashCopyToClipBoard`, `createHashDirectoryAlgorithm`, `createHashDirectoryRecursive` |

The keystore "last selected keystore / library" (`KeyStorePreferencesManager.lastSelectedKeystore[Lib]`) is **in memory
only** (static fields, per process), never persisted.

#### 4.2.2 Windows (registry)

* User root: `HKEY_CURRENT_USER\Software\JavaSoft\Prefs`.
* System root: `HKEY_LOCAL_MACHINE\Software\JavaSoft\Prefs` (64-bit JVM; a 32-bit JVM on 64-bit Windows uses
  `HKEY_LOCAL_MACHINE\Software\WOW6432Node\JavaSoft\Prefs`). Writing it requires administrator rights.
* A node path maps to a sub-key by replacing `/` with `\`, e.g. main preferences:
  `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\standalone\ui\preferences` and
  `HKLM\Software\JavaSoft\Prefs\es\gob\afirma\standalone\ui\preferences`.
* Every entry is a `REG_SZ` value. **Value names and value data are escaped by the JDK** (`WindowsPreferences`):
  * each ASCII upper-case letter `A`–`Z` is prefixed with `/` (e.g. `omitAskOnClose` → `omit/Ask/On/Close`);
  * `/` becomes `\` and `\` becomes `//`;
  * in **value data**, any character `< 0x20` or `> 0x7F` is written as `/u` + 4 lower-case hex digits
    (`í` → `/u00ed`);
  * in **names** (keys, node names), if any character is `< 0x20` or `> 0x7F`, the whole name is written as `/!` +
    the JDK "alt-base64" encoding of the UTF-16BE bytes (only relevant for smart-card names with accents).
  * Examples:

    | Java key = value | Registry value name = data |
    |---|---|
    | `preferencesBlocked` = `true` | `preferences/Blocked` = `true` |
    | `signatureHashAlgorithm` = `SHA512` | `signature/Hash/Algorithm` = `/S/H/A512` |
    | `defaultSignatureFormatPdf` = `PAdES` | `default/Signature/Format/Pdf` = `/P/Ad/E/S` |
    | `xadesSignFormat` = `XAdES Detached` | `xades/Sign/Format` = `/X/Ad/E/S /Detached` |
    | `padesBasicFormat` = `ETSI.CAdES.detached` | `pades/Basic/Format` = `/E/T/S/I./C/Ad/E/S.detached` |
    | `default.locale` = `es_ES` | `default.locale` = `es_/E/S` |
    | `configFileUrl` = `https://intra/af.afconfig` | `config/File/Url` = `https:\\intra\af.afconfig` |
    | `defaultLocalKeystorePath` = `C:\certs\a.p12` | `default/Local/Keystore/Path` = `/C://certs//a.p12` |
* A Rust implementation reading these legacy values must implement the reverse decoding (`/X`→`X`, `\`→`/`, `//`→`\`,
  `/uXXXX`→char, `/!…` alt-base64 names).
* The NSIS installer, on upgrade, backs up and restores the user node
  `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\standalone\ui\preferences` (temporary copy in
  `HKCU\Software\JavaSoft\Prefs\copia<N>`), and the uninstaller deletes `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\ui`,
  `…\afirma\standalone`, `…\afirma\core`, `…\afirma\plugin` and the empty parents (see §9).

#### 4.2.3 macOS (property lists)

* User root: `~/Library/Preferences/com.apple.java.util.prefs.plist`.
* System root: `/Library/Preferences/com.apple.java.util.prefs.plist` (requires root to write).
* The JDK `MacOSXPreferences` backend (CFPreferences domain `com.apple.java.util.prefs`) stores the tree as nested
  dictionaries rooted at the key `/`, each child node being a dictionary whose key is the node name followed by `/`
  (`"/" → "es/" → "gob/" → "afirma/" → "standalone/" → "ui/" → "preferences/" → { key = string; … }`). Values are
  strings. Verify on a real machine with `defaults read com.apple.java.util.prefs` (user) or
  `defaults read /Library/Preferences/com.apple.java.util.prefs` (system) before relying on the exact layout.
* No escaping is applied to key names or values.

#### 4.2.4 Linux / other Unix (XML files)

* User root: `~/.java/.userPrefs/` (overridable with the JVM property `java.util.prefs.userRoot`).
* System root: `/etc/.java/.systemPrefs/` (JVM property `java.util.prefs.systemRoot`, default `/etc/.java`); if it
  does not exist and cannot be created the JDK falls back to `$JAVA_HOME/.systemPrefs`.
* Each node is a directory (`…/es/gob/afirma/standalone/ui/preferences/`) containing `prefs.xml`:

  ```xml
  <?xml version="1.0" encoding="UTF-8" standalone="no"?>
  <!DOCTYPE map SYSTEM "http://java.sun.com/dtd/preferences.dtd">
  <map MAP_XML_VERSION="1.0">
    <entry key="preferencesBlocked" value="true"/>
    <entry key="signatureHashAlgorithm" value="SHA512"/>
  </map>
  ```
  (node directory names made only of printable ASCII other than `/`, `.`, `_` are used verbatim – true for all
  AutoFirma nodes; lock files `.user.lock.<user>`, `.systemlock`, `.userRootModFile.<user>`, `.systemRootModFile` also
  live in the roots).

#### 4.2.5 Recommendation for the Rust implementation

* Abstract a `PrefStore` with three readable layers (user, system, defaults) plus the internal set, keeping **the exact
  key names** of §4.5 (including misspellings such as `requireSignedPrerefences`, `massiveOverride`,
  `allowShadowAttack`).
* System layer sources, in order: native admin location of the new app (e.g. HKLM `Software\Policies\…` / MDM managed
  plist `/Library/Managed Preferences/…` / `/etc/autofirma/…`) **and** the legacy Java system locations above (decoded).
* User layer: new user store, migrated once from the legacy Java user locations.
* Persist immediately on write (Java relied on its background sync; see §4.3.3).

### 4.3 Value resolution, write semantics and types

#### 4.3.1 Reading (`PreferencesManager.get/getBoolean`)

```
get(key)        = user[key] ?? system[key] ?? defaults[key] ?? null
getBoolean(key) = parseBool(user[key]) ?? parseBool(system[key]) ?? (defaults[key] == "true")
get(key, src)   = value from exactly one layer: USER | SYSTEM | SYSTEM_INTERNAL | DEFAULT (no fallback)
```

* "system" means: the *updated* system copy (`…/ui/systempreferences`, user root) **if** the real system node exists
  **and** `allowUpdateConfig` is `true` in the system internal node **and** the updated copy exists; otherwise the real
  system node if it exists; otherwise there is no system layer. (`PreferencesManager.init`, lazily once per process.)
* `SYSTEM_INTERNAL` reads a merged map: all keys of the system internal node, overlaid by the user internal node for
  every key that is **not** system-exclusive (`configFileUrl`, `allowUpdateConfig` are exclusive). If the system
  internal node does not exist the merged map is `null` (all internal reads return `null`/`false`).
* The default layer is the file `preferences.properties` (Java `Properties` syntax, `\uXXXX` escapes). Keys absent from
  it have no default (`get` returns `null`).

#### 4.3.2 Writing (`put`, `putBoolean`, `remove`, `clearAll`)

```
put(key, value):
    reference = system[key] ?? defaults[key]
    if value == reference:            delete user[key]          # do not shadow admin/default
    elif value != get(key):           user[key] = value
putBoolean: same logic using boolean comparison.
remove(key):     delete user[key]
clearAll():      delete every key of the user main node (system and defaults untouched)
```

System writes (`putSystemPref`, `putBooleanSystemPref`, `clearAllSystemPrefs`, `flushSystemPrefs`) are only used by the
configurator/installer and by the remote auto-update. If the system node cannot be created/written (no admin rights),
they silently switch the *system* target to the user-root node `…/ui/systempreferences` (and the internal target to
`…/ui/internalpreferences` under the user root). `removeSystemPrefs()` (uninstall only) deletes the real system node
and the system internal node and prunes empty parent nodes.

#### 4.3.3 Persistence timing

`flush()` is called by: the Preferences dialog "Aceptar"/"Aplicar ahora", the proxy and secure-domain dialogs, the
"remember config" of the visible PDF signature dialog, the keystore-tab restore, and the confirm-to-sign "omit"
checkbox. Many other writes (sub-dialog OK of formats/policies, per-tab "Restaurar configuración", `.afconfig` import,
close-confirmation and DNIe-screen checkboxes, language change) are **not** flushed explicitly; Java persists them
anyway via its background sync (≈30 s) and at JVM exit. Consequence: **"Cancelar" in the Preferences dialog does not
roll back** changes already written by sub-dialogs or restore buttons. A Rust port should persist each write
immediately and document this (or implement real transactional cancel).

### 4.4 Locking ("blocked preferences") and administrator controls

#### 4.4.1 The lock flag

* Key **`preferencesBlocked`** (constant `PREFERENCE_GENERAL_BLOCKED`), boolean, default `false`, not shown in the UI.
  Intended to be set by an administrator in the **system** layer (or in an `.afconfig` file deployed system-wide).
* It is read once when the Preferences dialog is built (`PreferencesManager.getBoolean(...)`, normal user→system→default
  resolution) and passed as `blocked` to every tab.
* Effect: *only* the GUI. Specific controls are disabled (read-only) and some reset/import actions are skipped. It does
  **not** affect signing code paths, the CLI, protocol invocations, nor values already stored in the user layer.

#### 4.4.2 What is disabled when `blocked = true`

| Tab | Disabled controls / skipped actions | Still editable |
|---|---|---|
| General | "Importar configuración" button (file and Alt+click URL import); "Restaurar configuración" button; "Buscar actualizaciones al inicio"; "Habilitar JMulticard…"; "Algoritmo de huella para la firma" combo; "Permitir agregar nuevas firmas a documentos con firmas no válidas"; "Aceptar sólo conexiones con sitios seguros"; all six combos of the "Configurar formatos" sub-dialog | "Exportar configuración"; "No pedir confirmación al cerrar"; "Funcionamiento optimizado para VDI"; "Habilitar diálogo de carga…"; "Solicitar confirmación para firmar"; "Sobreescribir ficheros… firmas masivas"; Dominios seguros; Configurar proxy; Certificados de confianza (governed by `allowPersonalTruststore` instead); the "Reestablecer" button of the formats sub-dialog (quirk, §4.17) |
| PAdES | "Formato avanzado de firma" combo; "Comprobar PDF Shadow Attack"; "Configurar política" button; the per-tab "Restaurar configuración" only resets the non-protected subset (reason, city, contact, visible signature, obfuscation, visible stamp) | Visible signature, obfuscation, stamp, metadata text fields, "Permitir generar PDF certificado"; quirk: the "Tipo por defecto" certification combo is *enabled* when blocked (`setEnabled(isBlocked())` bug) |
| CAdES | "Incluir una copia de los datos firmados…" (implicit); the three multisignature radio buttons; "Configurar política"; per-tab restore does nothing | – |
| XAdES | "Formato de firma" combo; multisignature radios; "Configurar política"; per-tab restore only resets the metadata fields | Metadata fields (city, province, postal code, country, claimed role) |
| Factura Electrónica | Policy combo (inside the policy panel); per-tab restore only resets role and metadata | Signer role combo, metadata fields |
| Almacenes de claves | "Usar también en las llamadas a Autofirma desde el navegador"; "Permitir el uso de certificados caducados" | Default keystore combo, all other filters, smart-card management; per-tab restore is **not** affected by the lock (it resets everything, §4.9.8) |

#### 4.4.3 Protected keys list (`PreferencesManager.isProtectedPreference`)

`checkForUpdates`, `enabledJmulticard`, `signatureHashAlgorithm`, `defaultSignatureFormatPdf`,
`defaultSignatureFormatOoxml`, `defaultSignatureFormatFacturae`, `defaultSignatureFormatOdf`,
`defaultSignatureFormatXml`, `defaultSignatureFormatBin`, `allowInvalidSignatures`, `secureConnections`,
`xadesPolicyIdentifier`, `xadesPolicyIdentifierHash`, `xadesPolicyIdentifierHashAlgorithm`, `xadesPolicyQualifier`,
`xadesSignFormat`, `padesBasicFormat`, `padesPolicyIdentifier`, `padesPolicyIdentifierHash`,
`padesPolicyIdentifierHashAlgorithm`, `padesPolicyQualifier`, `allowShadowAttack`, `cadesPolicyIdentifier`,
`cadesPolicyIdentifierHash`, `cadesPolicyIdentifierHashAlgorithm`, `cadesPolicyQualifier`, `cadesImplicitMode`,
`facturaEPolicy`, `showExpiredCerts`.

Use: when a user-level `.afconfig` import runs while blocked, protected keys from the file are skipped. In practice the
import button is disabled when blocked, so the list is only documentation of "what the lock is meant to protect". The
Rust port should use this list as the authoritative set of lockable keys (and also lock `xadesMultisign`,
`cadesMultisign`, `useDefaultStoreInBrowserCalls`, `allowCertifiedPDF`/`padesCertificationLevel` and the FacturaE policy
detail keys, which the Java UI also disables or treats as policy but forgot in this list).

Internal / admin-only keys (never shown in the UI):

| Key | Store read from | Type | Default | Meaning |
|---|---|---|---|---|
| `configFileUrl` | internal, **system-exclusive** | string (https URL or local path) | – | Where the system configuration was installed from; used by auto-update only when it starts with `https://` |
| `allowUpdateConfig` | internal, **system-exclusive**, read *only* from the system root | boolean | false | Enables daily re-download of `configFileUrl` and makes the "updated" user-side copies (`…/systempreferences`, `…/systemkeystores`) authoritative |
| `configFileSHA256` | internal (user overlay allowed) | upper-case hex SHA-256 | – | Hash of the last imported config file; a new download is applied only if its hash differs |
| `configDate` | internal (user overlay allowed) | `YYYYMMdd` (Java week-year pattern, see §4.17) | – | Date of last remote check |
| `requireSignedPrerefences` | internal (`SYSTEM_INTERNAL`) | boolean | false | Intended: reject unsigned `.afconfig` on GUI import (buggy, §4.10.3) |
| `certHashToSignedPrerefences` | internal (`SYSTEM_INTERNAL`) | Base64(SHA-256(DER cert)) | – | If set, a signed `.afconfig` must be signed by exactly this certificate |
| `allowPersonalTruststore` | main (user→system→default) | boolean | true | If false: the AutoFirma personal trust store (`~/.afirma/TrustedCertsKeystore.jks`) is not loaded for TLS and the "Certificados de confianza" button is disabled with tooltip `"Botón para configurar los certificados de confianza. Bloqueado por el administrador del equipo."` (`PreferencesPanel.212`) |
| `allowAutoImportTrustedCerts` | main | boolean | true | If false (or `allowPersonalTruststore` false) the JVM property `blockAutoImportTrustedCerts=true` is set, which suppresses the "import this untrusted server certificate?" prompt during HTTPS connections (`TrustedCertificatesDialog.22/.23`) |

#### 4.4.4 Other administrator switches (environment / JVM properties)

| Variable / property | Effect on preferences |
|---|---|
| env `AUTOFIRMA_AVOID_UPDATE_CHECK=true` or JVM `-Des.gob.afirma.doNotCheckUpdates=true` | Update checking disabled; the "Buscar actualizaciones al inicio" checkbox is not shown (and `checkForUpdates` is not saved) |
| env `AFIRMA_NSS_DISABLE_DNIE_NATIVE_DRIVER` or `AFIRMA_NSS_DISABLE_CERES_NATIVE_DRIVER` defined (any value) | The "Habilitar JMulticard…" checkbox is shown unchecked and disabled ("configured by system") |

#### 4.4.5 How administrators deploy configuration

1. **Installer / configurator options** (see §9): `-config_path <file|https-url>` imports a plist into the **system**
   layer (no signature check, no confirmation, smart cards included), `-update_config` additionally sets
   `allowUpdateConfig=true` (only kept if the path is `https://`), `-default_language <ll_CC>` writes
   `default.locale` to the system layer. The Windows NSIS/MSI installers expose them as `/CONFIG_PATH=`,
   `/UPDATE_CONFIG=true`, `/DEFAULT_LANGUAGE=` (MSI properties `CONFIG_PATH`, `UPDATE_CONFIG`, `DEFAULT_LANGUAGE`).
2. **Direct write** of the system node (registry HKLM / `/Library/Preferences/com.apple.java.util.prefs.plist` /
   `/etc/.java/.systemPrefs/...`) with the exact key names of §4.5 (encoded per §4.2.2 on Windows).
3. **Remote configuration** (§4.11) once `configFileUrl` + `allowUpdateConfig` are present in the system internal node.

Gotchas of the Java design that a corporate deployment must know (and that a Rust port should fix or at least
document):

* **User values always win over system values.** A user who set a value *before* the admin policy was deployed keeps it,
  even with `preferencesBlocked=true`. The lock only greys out controls.
* **The lock flag itself is resolved user-first**: a user who writes `preferencesBlocked=false` in their own node (e.g.
  `HKCU`) unlocks the GUI.
* `allowPersonalTruststore` / `allowAutoImportTrustedCerts` are also user-overridable, and the non-exclusive internal
  admin keys (`requireSignedPrerefences`, `certHashToSignedPrerefences`) can be overlaid from the user internal node.
* Recommended Rust semantics: when `preferencesBlocked` is true **in the system layer**, the protected keys (§4.4.3)
  must resolve system → default and ignore user values; admin-only keys must be read from the system layer only.

### 4.5 Complete key reference

Legend: **Type** – `bool` = `"true"`/`"false"`; `str`; `enum` (allowed literal values listed); `int` = decimal string.
**Prot.** = in the protected list (§4.4.3). **Dis.** = control disabled when `preferencesBlocked=true`.
"Default" is the value in `preferences.properties`; "—" means absent (null).

#### 4.5.1 Hidden / global keys (not editable in the Preferences dialog)

| Key | Constant | Type | Default | Where edited | Effect | Prot. |
|---|---|---|---|---|---|---|
| `default.locale` | `PREFERENCES_LOCALE` | str (`ll_CC`) | `es_ES` | Menu "Idioma" (radio items es_ES, ca_ES, gl_ES, eu_ES, va_ES, en_US + imported languages); configurator `-default_language` (system layer) | UI language at next start (restart warning shown); help file `index_<locale>.html` (§11) | no |
| `preferencesBlocked` | `PREFERENCE_GENERAL_BLOCKED` | bool | `false` | admin only | §4.4 | n/a |
| `checkJavaVersion` | `PREFERENCE_GENERAL_CHECK_JAVA_VERSION` | bool | `true` | "No volver a mostrar" checkbox of the unsupported-Java warning (`SimpleAfirma.49/50/51`); reset to `true` automatically when the Java version becomes supported | Show the "Versión de Java no soportada" warning at start. Obsolete for a Rust port | no |
| `lastCheckDate` | — (only in defaults file) | str | empty | never | Dead default; the updater really stores `lastCheckDate` in node `/es/gob/afirma/standalone` (§8) | no |
| `jmulticardCachePassword` | — (only in defaults file) | bool | `false` | never | Dead key, unused | no |

#### 4.5.2 Tab "General" (`PreferencesPanelGeneral`, tab title `"General"`, tooltip `"Opciones generales de configuración"`)

Box `"Opciones generales"` (`PreferencesPanel.108`): buttons `"Importar configuración"` (mnemonic I),
`"Exportar configuración"` (G), `"Restaurar configuración"` (R) – §4.9.2, §4.10.

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `omitAskOnClose` | `PREFERENCE_GENERAL_OMIT_ASKONCLOSE` | bool | `false` | Checkbox `"No pedir confirmación al cerrar la aplicación"` (`.36`); also the `"No volver a mostrar este mensaje"` checkbox in the close-confirmation dialog (`ClosePanel.0`, written immediately) | If true, closing the main window exits without asking `"¿Desea cerrar la aplicación de firma?"` | – / – |
| `checkForUpdates` | `PREFERENCE_GENERAL_UPDATECHECK` | bool | `true` | Checkbox `"Buscar actualizaciones al inicio"` (`.87`), only visible when updates are enabled (§4.4.4) | Check for a newer version at desktop start-up (§8) | Prot. / Dis. |
| `enabledJmulticard` | `PREFERENCE_GENERAL_ENABLED_JMULTICARD` | bool | `true` | Checkbox `"Habilitar JMulticard para el uso de tarjetas de la FNMT y DNIe (requiere reiniciar Autofirma)"` (`.165`), shown on **Windows and Linux only** | true: built-in Java drivers for DNIe and FNMT CERES cards are added to the keystore list; false: JVM properties `es.gob.afirma.keystores.mozilla.disableDnieNativeDriver=true` and `…disableCeresNativeDriver=true` are set, so only the OS/NSS PKCS#11 drivers are used. Applied at start, when loading keystores and on browser invocations | Prot. / Dis. |
| `vdiOptimization` | `PREFERENCE_GENERAL_VDI_OPTIMIZATION` | bool | `false` | Checkbox `"Funcionamiento optimizado para VDI. No recomendado en otros entornos."` (`.190`), **Windows only** | Sets JVM property `websockets.optimizedForVdi` for the browser WebSocket server (adds small delays to avoid channel blocking on VDI; slows large transfers) | – / – |
| `enableProgressDialog` | `PREFERENCE_GENERAL_ENABLE_PROGRESS_DIALOG` | bool | `true` | Checkbox `"Habilitar diálogo de carga para llamadas desde el navegador"` (`.211`) | Shows the small progress/wait window during browser-invoked operations (`ProgressInfoDialog`) | – / – |

Box `"Opciones de firma"` (`.17`):

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `signatureHashAlgorithm` | `PREFERENCE_GENERAL_SIGNATURE_ALGORITHM` | enum `SHA1`\|`SHA512`\|`SHA384`\|`SHA256` (combo order) | `SHA256` | Combo `"Algoritmo de huella para la firma:"` (`.18`); invalid stored value → default selected | Digest of every **GUI** signature that has no explicit digest; signature algorithm = `<digest>with<keyAlg>` (e.g. `SHA256withRSA`) | Prot. / Dis. |
| `defaultSignatureFormat*` (6 keys) | see §4.6 | enum | see §4.6 | Button `"Configurar formatos"` (mnemonic o) next to `"Cambiar formato de firma para cada tipo de fichero:"` (`.161`) → sub-dialog `"Formatos de firma"` | Format chosen automatically per file type in the GUI | Prot. / Dis. |
| `confirmToSign` | `PREFERENCE_GENERAL_CONFIRMTOSIGN` | bool | `true` | Checkbox `"Solicitar confirmación para firmar"` (`.179`); also set to `false` by the checkbox `"Omitir esta confirmación en futuras operaciones de firma."` of the confirmation dialog (flushed) | Before a GUI signature, show `"Autorizar firma"` dialog (`ConfirmSignatureDialog`, see §2) | – / – |
| `allowInvalidSignatures` | `PREFERENCE_GENERAL_ALLOW_INVALID_SIGNATURES` | bool | `false` | Checkbox `"Permitir agregar nuevas firmas a documentos con firmas no válidas"` (`.178`) | If false: GUI single sign of a file whose existing signature validates KO shows `"No se permite agregar nuevas firmas a documentos con firmas no válidas."` (`SimpleAfirma.9`) and aborts; in multi-file signing such files are skipped | Prot. / Dis. |
| `massiveOverride` | `PREFERENCE_GENERAL_MASSIVE_OVERWRITE` | bool | `false` | Checkbox `"Sobreescribir ficheros en el directorio de salida en las firmas masivas"` (`.160`) | GUI multi-file signing: true overwrites `<name>_signed.<ext>`; false appends `(1)`, `(2)`… before the extension (§6) | – / – |

Box `"Configuración de red"` (`.125`):

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `secureConnections` | `PREFERENCE_GENERAL_SECURE_CONNECTIONS` | bool | `true` | Checkbox `"Aceptar sólo conexiones con sitios seguros (Recomendado)"` (`.173`, tooltip `.174`) | false: JVM property `disableSslChecks=true` → TLS certificate validation disabled for **all** outgoing HTTPS (retrieve/storage servers, triphase servers, policy download…). true: TLS validated against JRE trust store + AutoFirma personal trust store (if allowed). Applied immediately on save and at start-up (`SSLContextConfigurationTask`) | Prot. / Dis. |
| `secureDomainsList` | `PREFERENCE_GENERAL_SECURE_DOMAINS_LIST` | str (comma-separated patterns) | — | Button `"Dominios seguros"` (D) → §4.13 | Hosts for which TLS validation is skipped even when `secureConnections=true` | – / – |
| `proxyType`, `proxySelected`, `proxyHost`, `proxyPort`, `proxyUsername`, `proxyPassword`, `proxyExcludedUrls` | `PREFERENCE_GENERAL_PROXY_*` | see §4.12 | `NONE`/`false`/empty/empty/—/—/— | Button `"Configurar proxy"` (y) next to `"Cambiar configuración de proxy para las conexiones de red:"` → §4.12 | Outgoing HTTP(S)/FTP/SOCKS proxy | – / – |
| (trusted certificates store) | — | file | — | Button `"Certificados de confianza"` (t) → §4.14 | Personal TLS trust store | governed by `allowPersonalTruststore` |

#### 4.5.3 Sub-dialog "Formatos de firma" (`DefaultFormatPanel`)

Six keys `defaultSignatureFormat{Pdf,Ooxml,Facturae,Odf,Xml,Bin}`, see §4.6 for values/defaults. Button
`"Reestablecer"` (mnemonic r) loads the built-in defaults into the combos. **OK writes immediately** (independently of
the main dialog's Aceptar/Cancelar).

#### 4.5.4 Tab "Firmas PAdES (PDF)" (`PreferencesPanelPades`, tooltip `"Opciones de configuración para las firmas PAdES de documentos PDF"`)

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `padesPolicyIdentifier` | `PREFERENCE_PADES_POLICY_IDENTIFIER` | str (OID, may carry `urn:oid:`) | empty | Box `"Configuración de la política de firma"`: label `"Política de firma:"` + current name + button `"Configurar política"` (P) → policy sub-dialog §4.7 | extraParam `policyIdentifier` | Prot. / Dis. |
| `padesPolicyIdentifierHash` | `PREFERENCE_PADES_POLICY_HASH` | str (Base64) | empty | idem | `policyIdentifierHash` | Prot. / Dis. |
| `padesPolicyIdentifierHashAlgorithm` | `PREFERENCE_PADES_POLICY_HASH_ALGORITHM` | enum `SHA1`\|`SHA-512`\|`SHA-384`\|`SHA-256` | empty | idem | `policyIdentifierHashAlgorithm` | Prot. / Dis. |
| `padesPolicyQualifier` | `PREFERENCE_PADES_POLICY_QUALIFIER` | str (URL) | empty | idem | `policyQualifier` | Prot. / Dis. |
| `padesBasicFormat` | `PREFERENCE_PADES_FORMAT` | enum `ETSI.CAdES.detached` (shown `"PAdES-BES"`) \| `adbe.pkcs7.detached` (shown `"PAdES Básico"`) | `ETSI.CAdES.detached` | Combo `"Formato avanzado de firma:"` (`.115`); forced to PAdES-BES and disabled while a policy is selected | extraParam `signatureSubFilter` | Prot. / Dis. |
| `padesVisibleSignature` | `PREFERENCE_PADES_VISIBLE` | bool | `false` | Checkbox `"Realizar por defecto firmas visibles PDF"` (`.79`) | Initial state of `"Hacer la firma visible dentro del PDF"` in the sign screen; in multi-file signing, whether to ask for the visible-signature area | – / – |
| `padesObfuscateCertInfo` | `PREFERENCE_PADES_OBFUSCATE_CERT_INFO` | bool | `true` | Checkbox `"Ofuscar identificadores de usuario de los certificados de las firmas visibles"` (`.175`) | extraParam `obfuscateCertText` (masks DNI/NIE digits of CN/DN in the visible text) | – / – |
| `padesVisibleStamp` | `PREFERENCE_PADES_STAMP` | bool | `false` | Checkbox `"Aplicar marca visible a documentos PDF"` (`.172`) | Initial state of `"Insertar una marca visible dentro del PDF"` in the sign screen (see §3) | – / – |
| `allowShadowAttack` | `PREFERENCE_PADES_CHECK_SHADOW_ATTACK` | bool – **name is inverted: `true` means "DO check"** | `false` | Checkbox `"Comprobar PDF Shadow Attack"` (`.187`); checking it shows warning `"Al activar esta opción, el proceso de validación para PDF puede retrasarse."` | When validating a loaded PDF: false → validation param `allowShadowAttack=true` (skip PSA check); true → PSA check over all pages (`pagesToCheckShadowAttack=all`) | Prot. / Dis. |
| `allowCertifiedPDF` | `PREFERENCE_PADES_CHECK_ALLOW_CERTIFIED_PDF` | bool | `false` | Checkbox `"Permitir generar PDF certificado."` (`.204`); enables the next combo | Whether the sign screen offers `"Generar firma PDF certificado"` | – / – |
| `padesCertificationLevel` | `PREFERENCE_PADES_DEFAULT_CERTIFICATION_LEVEL` | enum `0`\|`1`\|`2`\|`3` | `0` | Combo `"Tipo por defecto:"` (`.203`): `"Sin certificar"`, `"Certificada de autor"`, `"Certificada de autor para formularios"`, `"Certificada común"` | extraParam `certificationLevel` (only added when ≠ `0`) | – / quirk |
| `padesSignReason` | `PREFERENCE_PADES_SIGN_REASON` | str | empty | Box `"Metadatos de las firmas"`: `"Razón por la que se firma el documento"` (`.20`) | extraParam `signReason` (if non-blank) | – / – |
| `padesSignProductionCity` | `PREFERENCE_PADES_SIGN_PRODUCTION_CITY` | str | empty | `"Ciudad en la que se realiza la firma"` (`.21`) | `signatureProductionCity` | – / – |
| `padesSignerContact` | `PREFERENCE_PADES_SIGNER_CONTACT` | str | empty | `"Contacto del firmante (usualmente una dirección de correo electrónico)"` (`.22`) | `signerContact` | – / – |

Per-tab button `"Restaurar configuración"` (R), confirm `"¿Desea restaurar la configuración de las firmas PAdES?"` (§4.9.8).

#### 4.5.5 Visible PDF signature appearance (no Preferences tab; written by the visible-signature dialog, §3)

Saved when the checkbox `"Recordar configuración"` (`SignPdfUiPreview.33`, default checked) is ticked at the end of the
visible signature dialog; the dialog's "restore defaults" action reloads the built-in defaults.

| Key | Constant | Type | Default | Effect |
|---|---|---|---|---|
| `pdfLayer2Text` | `PREFERENCE_PDF_SIGN_LAYER2TEXT` | str | `Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$` | extraParam `layer2Text` (empty text stored → font keys not updated) |
| `pdfLayer2FontFamily` | `PREFERENCE_PDF_SIGN_LAYER2FONTFAMILY` | enum `0` Courier \| `1` Helvetica \| `2` Times Roman | `0` | `layer2FontFamily` |
| `pdfLayer2FontSize` | `PREFERENCE_PDF_SIGN_LAYER2FONTSIZE` | int | `12` | `layer2FontSize` |
| `pdfLayer2FontStyle` | `PREFERENCE_PDF_SIGN_LAYER2FONTSTYLE` | int `0` normal, `1` bold, `2` italic, `3` bold+italic, `4` underline, `8` strikethrough | `0` | `layer2FontStyle` |
| `pdfLayer2FontColor` | `PREFERENCE_PDF_SIGN_LAYER2FONTCOLOR` | enum `black`\|`white`\|`lightGray`\|`gray`\|`darkGray`\|`red`\|`pink` | `black` | `layer2FontColor` |
| `pdfSignatureRotation` | `PREFERENCE_PDF_SIGN_SIGNATUREROTATION` | enum `0`\|`90`\|`180`\|`270` | `0` | `signatureRotation` |
| `pdfSignatureImage` | `PREFERENCE_PDF_SIGN_IMAGE` | str (local image path) | empty | Rubric image loaded and sent as `signatureRubricImage`; removed when no image is used |

#### 4.5.6 Tab "Firmas CAdES" (`PreferencesPanelCades`, tooltip `"Opciones de configuración para las firmas CAdES de ficheros binarios"`)

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `cadesPolicyIdentifier` / `cadesPolicyIdentifierHash` / `cadesPolicyIdentifierHashAlgorithm` / `cadesPolicyQualifier` | `PREFERENCE_CADES_POLICY_*` | as PAdES | empty | Policy box + `"Configurar política"` (§4.7) | `policyIdentifier`, `policyIdentifierHash`, `policyIdentifierHashAlgorithm`, `policyQualifier` | Prot. / Dis. |
| `cadesImplicitMode` | `PREFERENCE_CADES_IMPLICIT` | bool | `true` | Box `"Opciones de firma"`: checkbox `"Incluir una copia de los datos firmados en la propia firma"` (`.1`) | extraParam `mode` = `implicit` (true) / `explicit` (false) | Prot. / Dis. |
| `cadesMultisign` | `PREFERENCE_CADES_MULTISIGN` | enum `cosign`\|`countersignLeafs`\|`countersignTree` | `cosign` | Box `"Operación en multifirmas"`: radios `"Cofirma"`, `"Contrafirma (únicamente de los nodos hoja)"`, `"Contrafirma (de todo el árbol)"` | Operation applied in the GUI when the loaded file is already a CAdES signature (any unknown value → `countersignTree`) | – / Dis. |

#### 4.5.7 Tab "Firmas XAdES" (`PreferencesPanelXades`, tooltip `"Opciones de configuración para las firmas XAdES de documentos XML"`)

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `xadesPolicyIdentifier` / `…Hash` / `…HashAlgorithm` / `xadesPolicyQualifier` | `PREFERENCE_XADES_POLICY_*` (`…_HASH` = `xadesPolicyIdentifierHash`, `…_HASH_ALGORITHM` = `xadesPolicyIdentifierHashAlgorithm`) | identifier: URI (`urn:oid:…` auto-added for OIDs on focus loss) | empty | Policy box (§4.7) | `policyIdentifier`, … | Prot. / Dis. |
| `xadesSignFormat` | `PREFERENCE_XADES_SIGN_FORMAT` | enum `XAdES Enveloped`\|`XAdES Enveloping`\|`XAdES Detached` (combo order) | `XAdES Detached` | Box `"Opciones de firma"`: combo `"Formato de firma:"` (`.15`). With an AGE policy (1.8/1.9) only Enveloped/Detached are offered | extraParam `format` | Prot. / Dis. |
| `xadesMultisign` | `PREFERENCE_XADES_MULTISIGN` | enum as CAdES | `cosign` | Box `"Operación en multifirmas"` radios | Operation when the loaded file is already a XAdES signature | – / Dis. |
| `xadesSignatureProductionCity` | `PREFERENCE_XADES_SIGNATURE_PRODUCTION_CITY` | str | empty | Box `"Metadatos de las firmas"`: `"Ciudad en la que se realiza la firma"` (`.11`) | `signatureProductionCity` | – / – |
| `xadesSignatureProductionProvince` | `…_PROVINCE` | str | empty | `"Provincia en la que se realiza la firma"` (`.14`) | `signatureProductionProvince` | – / – |
| `xadesSignatureProductionPostalCode` | `…_POSTAL_CODE` | str | empty | `"Código postal del lugar en el que se realiza la firma"` (`.102`) | `signatureProductionPostalCode` | – / – |
| `xadesSignatureProductionCountry` | `…_COUNTRY` | str | empty | `"País en el que se realiza la firma"` (`.12`) | `signatureProductionCountry` | – / – |
| `xadesSignerClaimedRole` | `PREFERENCE_XADES_SIGNER_CLAIMED_ROLE` | str | empty | `"Cargo atribuido al firmante"` (`PreferencesPanelXades.0`) | `signerClaimedRoles` | – / – |

#### 4.5.8 Tab "Factura Electrónica" (`PreferencesPanelFacturaE`, tooltip `"Opciones de configuración para la Factura Electrónica de documentos"`)

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `facturaEPolicy` | `PREFERENCE_FACTURAE_POLICY` | enum `3.1`\|`3.0` | `3.1` | Box `"Configuración de la política de firma"`, combo `"Política de firma:"` with `"Política de Factura Electrónica 3.1"`, `"Política de Factura Electrónica 3.0"` (no "none", no custom) | Selects the policy whose id/hash/algorithm are written to the next keys | Prot. / Dis. |
| `facturaePolicyIdentifier` | `PREFERENCE_FACTURAE_POLICY_IDENTIFIER` | str (URL) | `http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf` | derived | `policyIdentifier` | – |
| `facturaePolicyIdentifierHash` | `PREFERENCE_FACTURAE_POLICY_IDENTIFIER_HASH` | Base64 | `Ohixl6upD6av8N7pEvDABhEL6hM=` | derived | `policyIdentifierHash` | – |
| `facturaePolicyIdentifierHashAlgorithm` | `PREFERENCE_FACTURAE_POLICY_IDENTIFIER_HASH_ALGORITHM` | enum | `SHA1` | derived | `policyIdentifierHashAlgorithm` | – |
| `facturaePolicyQualifier` | `PREFERENCE_FACTURAE_POLICY_QUALIFIER` | str | — | removed on save (both FacturaE policies have no qualifier) | **not** passed to the signer | – |
| `facturaeSignerRole` | `PREFERENCE_FACTURAE_SIGNER_ROLE` | enum `Emisor`\|`Receptor`\|`Tercero` | `Emisor` | Box `"Opciones de firma"`, combo `"Papel del firmante de la factura electrónica:"` (items `"Emisor"`, `"Receptor"`, `"Tercero"`) | extraParam `signerClaimedRoles` | – / – |
| `facturaeSignatureProductionCity` / `…Province` / `…PostalCode` / `…Country` | `PREFERENCE_FACTURAE_SIGNATURE_PRODUCTION_*` | str | empty | Box `"Metadatos de las firmas"`, same labels as XAdES | `signatureProductionCity/Province/PostalCode/Country` | – / – |

#### 4.5.9 Tab "Almacenes de claves" (`PreferencesPanelKeystores`, tooltip `"Opciones de configuración de certificados"`)

| Key | Constant | Type | Default | UI control (es) | Effect | Prot. / Dis. |
|---|---|---|---|---|---|---|
| `defaultKeystore` | `PREFERENCE_KEYSTORE_DEFAULT_STORE` | str: `default` or a keystore display name (`Windows`, `Llavero de Mac`, `NSS`, `Mozilla / Firefox (unificado)`, `PKCS#12 / PFX`, `DNIe y tarjetas FNMT-TIF`) or a registered smart-card name | `default` | Box `"Almacén por defecto"` (`PreferencesPanelKeyStores.1`): combo whose items are, per OS: Windows → `Windows` [+ `Mozilla / Firefox (unificado)` if Firefox installed]; macOS → `Llavero de Mac` [+ Mozilla]; Linux → `NSS`; then always `PKCS#12 / PFX`, `DNIe y tarjetas FNMT-TIF`, then each registered smart card. **Index 0 is stored as `default`** | Keystore loaded by the desktop GUI at start; and, if `useDefaultStoreInBrowserCalls`, for browser calls. Name matching is case-insensitive against keystore names; `Mozilla…` from the browser becomes "Mozilla + OS store" variant; invalid/unavailable (e.g. Firefox uninstalled, wrong OS) → OS default | – / – |
| `defaultLocalKeystorePath` | `PREFERENCE_LOCAL_KEYSTORE_PATH` | str (path) | empty | Set when choosing `PKCS#12 / PFX` (file chooser `"Selección de almacén local"`, filter `"Almacenes de claves (*.p12, *.pfx)"`; cancel → back to index 0) or a smart card (its PKCS#11 library path) | File/library used to open the default PKCS#12/PKCS#11 store | – / – |
| `useDefaultStoreInBrowserCalls` | `PREFERENCE_USE_DEFAULT_STORE_IN_BROWSER_CALLS` | bool | `false` | Checkbox `"Usar también en las llamadas a Autofirma desde el navegador"` (`.3`) | Protocol operations (sign, batch, selectcert, sign&save): if no keystore was already chosen in this session, use `defaultKeystore` (if ≠ `default`) instead of the one requested by the web page; for PKCS#12/PKCS#11 also use `defaultLocalKeystorePath` | – / Dis. |
| `hideDnieStartScreen` | `PREFERENCE_GENERAL_HIDE_DNIE_START_SCREEN` | bool | `false` | Checkbox `"Omitir pantalla inicial de DNIe."` (`PreferencesPanel.81`); also checkbox `"No volver a mostrar esta pantalla inicial y trabajar siempre con el almacén por defecto"` on the DNIe start screen (written immediately) | If false and a smart-card reader is present and no file was passed, the desktop app starts on the DNIe wait screen (§2) | – / – |
| `showExpiredCerts` | `PREFERENCE_KEYSTORE_SHOWEXPIREDCERTS` | bool | `false` | Box `"Filtros de certificados"`: `"Permitir el uso de certificados caducados"` (`.6`) | Certificate selection dialog lists expired certificates | Prot. / Dis. |
| `useOnlySignatureCertificates` | `PREFERENCE_KEYSTORE_SIGN_ONLY_CERTS` | bool | `false` | `"Usar solo certificados específicos para firma en las firmas electrónicas (atributo de no repudio)"` (`.7`) | Adds a key-usage filter (nonRepudiation) | – / – |
| `useOnlyAliasCertificates` | `PREFERENCE_KEYSTORE_ALIAS_ONLY_CERTS` | bool | `false` | `"Usar exclusivamente certificados de seudónimo"` (`.8`) | Adds pseudonym-only filter | – / – |
| `skipAuthCertDnie` | `PREFERENCE_KEYSTORE_SKIP_AUTH_CERT_DNIE` | bool | `true` | `"Omitir certificado de autenticación de DNIe"` (`.32`) | Hides the DNIe authentication certificate | – / – |
| (smart cards) | — | §4.15 | — | Box `"Tarjetas inteligentes"` (`.9`) | PKCS#11 registry | – |

Filters are combined (logical AND, via a "multiple" filter) and apply to the GUI certificate selection; protocol calls
use the filters requested by the web page (see the protocol spec). Button `"Ver contenido"` (V) opens the certificate
selection dialog over the selected store in view-only mode, titled `"Contenido del almacén '<name>'"` with the note
`"Es posible que no todos los certificados mostrados estén disponibles para firmar electrónicamente."`.

#### 4.5.10 Proxy, secure domains and trust (stored in the main node; edited from the General tab)

See §4.12 (proxy), §4.13 (secure domains), §4.14 (trust store). Proxy keys: `proxySelected` (legacy bool, default
`false`), `proxyType` (enum `NONE`\|`SYSTEM`\|`CUSTOM`, default `NONE`), `proxyHost` (empty), `proxyPort` (empty),
`proxyUsername` (—), `proxyPassword` (— , ciphered), `proxyExcludedUrls` (—).

### 4.6 Default signature format per file type

Format strings are the signer names of `AOSignConstants`: `PAdES`, `CAdES`, `XAdES`, `FacturaE`,
`OOXML (Office Open XML)`, `ODF (Open Document Format)`.

| File type (detection order in the GUI) | Key | Built-in default | Allowed values (combo order) | Label in "Formatos de firma" |
|---|---|---|---|---|
| 1. PDF | `defaultSignatureFormatPdf` | `PAdES` | `PAdES`, `CAdES`, `XAdES` | `"Documentos PDF"` |
| 2. Factura electrónica (FacturaE XML) | `defaultSignatureFormatFacturae` | `FacturaE` | `FacturaE`, `XAdES`, `CAdES` | `"Facturas electrónicas"` |
| 3. OOXML (docx/xlsx/pptx) | `defaultSignatureFormatOoxml` | **`CAdES`** | `OOXML (Office Open XML)`, `CAdES`, `XAdES` | `"Documentos OOXML de Microsoft Office"` |
| 4. ODF (odt/ods/odp) | `defaultSignatureFormatOdf` | **`CAdES`** | `ODF (Open Document Format)`, `CAdES`, `XAdES` | `"Ficheros ODF de LibreOffice u OpenOffice"` |
| 5. Existing CAdES/XAdES signature | — | — | the detected signer; operation from `cadesMultisign`/`xadesMultisign` | — |
| 6. Other XML | `defaultSignatureFormatXml` | `XAdES` | `XAdES`, `CAdES` | `"Ficheros XML genéricos"` |
| 7. Anything else (binary) | `defaultSignatureFormatBin` | `CAdES` | `CAdES`, `XAdES` | `"Resto de ficheros"` |

Gotcha: contrary to the common assumption, the shipped defaults for **OOXML and ODF are CAdES**, not the native
OOXML/ODF formats (the native formats are offered first in the combos and marked `"(Recomendado)"` in the per-file
"change format" dialog, see §2). An already-signed PDF is still type PDF but the operation becomes co-sign. Full file
detection logic (magic bytes, FacturaE detection) is in §2.

### 4.7 Signature policies

#### 4.7.1 Policy sub-dialog (`PolicyPanel`, title `"Configuración de la política de firma"`)

Used by the PAdES, CAdES and XAdES tabs (button `"Configurar política"`) and embedded in the FacturaE tab.

* Combo `"Política de firma:"` with, for PAdES/CAdES/XAdES: `"Ninguna política"` (index 0), `"Política de firma de la AGE 1.9"`,
  `"Política de firma a medida"` (last). For FacturaE: `"Política de Factura Electrónica 3.1"`,
  `"Política de Factura Electrónica 3.0"` only, and the four fields are hidden.
* Fields (PAdES/CAdES/XAdES): identifier (label `"Identificador de la política (debe ser un OID)"` for CAdES/PAdES,
  `"Identificador de la política (debe ser una URI)"` for XAdES), `"Huella digital del identificador de la política (en Base64)"`,
  combo `"Algoritmo de la huella digital del identificador de la política"` (`SHA1`, `SHA-512`, `SHA-384`, `SHA-256`),
  `"Calificador de la política (URL)"`. Fields are enabled (read-only) for predefined policies, editable only for
  "a medida", disabled for "Ninguna".
* On identifier focus loss: for XAdES, a bare OID is rewritten to `urn:oid:<OID>`; for other formats any `urn:oid:`
  prefix is removed.
* When the stored policy equals a predefined one (same identifier, hash and hash algorithm) that item is pre-selected;
  otherwise the stored policy appears under "a medida".
* OK → validation (below) → on success the four keys are **written immediately** (or removed for "Ninguna"); on
  failure an error is shown and the dialog reopens. Side effects: PAdES with any policy forces `padesBasicFormat` to
  PAdES-BES and disables the combo; XAdES with an AGE policy restricts `xadesSignFormat` to Enveloped/Detached.

#### 4.7.2 Validation (`checkPreferences`, error codes `SimpleErrorCode.Functional`, message key `PreferencesPanelPolicy.<code-521000>`)

| Check | Code | Message (es) |
|---|---|---|
| identifier empty | 521001 | `"El identificador de política no puede ser nulo ni vacío"` |
| identifier not a URI | 521002 | `"El identificador debe ser una URI válida"` |
| identifier (after removing `urn:oid:`) not an OID – **applies to XAdES too** | 521007 | `"El identificador debe tener un formato OID válido"` |
| XAdES only: hash empty | 521008 | `"La huella digital no puede estar vacía"` |
| hash empty (CAdES/PAdES) or `0` (any): identifier must be downloadable as URL and digested (default SHA-512) | 521004 | `"Si no se especifica la huella digital, el identificador debe ser una URI accesible"` |
| hash given but no algorithm | 521003 | `"Si se indica la huella digital es obligatorio indicar también el algoritmo"` |
| hash not Base64 | 521005 | `"La huella digital debe estar en formato Base64"` |
| qualifier not a URL | 521009 | `"El calificador debe ser una URL válida"` |
| other | 521000 | `"Ha ocurrido un error configurando la política"` |

The same checks run for XAdES, PAdES and CAdES when pressing Aceptar/Aplicar in the main dialog (FacturaE's own check –
custom policy must be an OID – is never invoked because FacturaE has no custom option). Error titles in the main dialog:
`"Los datos de la política de firma XAdES|PAdES|CAdES son inválidos"` (`PreferencesPanel.6/.7/.38`).

#### 4.7.3 Predefined policy values (`afirma-core/src/main/resources/policy.properties` and code)

| Policy | Formats | Identifier | Hash (Base64) | Hash alg. stored | Qualifier |
|---|---|---|---|---|---|
| AGE 1.9 (`"Política de firma de la AGE 1.9"`) | XAdES, CAdES, PAdES | `urn:oid:2.16.724.1.3.1.1.2.1.9` | `G7roucf600+f03r/o0bAOQ6WAs0=` (same for all three) | `SHA1` | `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` |
| AGE 1.8 (recognised, not offered in combos) | XAdES | `urn:oid:2.16.724.1.3.1.1.2.1.8` | `V8lVVNGDCPen6VELRD1Ja8HARFk=` | `SHA1` | `https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf` |
| AGE 1.8 | CAdES, PAdES | idem | `7SxX3erFuH31TvAw9LZ70N7p1vA=` | `SHA1` | idem |
| FacturaE 3.1 | FacturaE | `http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf` | `Ohixl6upD6av8N7pEvDABhEL6hM=` | `SHA1` | none |
| FacturaE 3.0 | FacturaE | `http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf` (contains spaces) | `xmfh8D/Ec/hHeE1IB4zPd61zHIY=` | `SHA1` | none |

`AgePolicy.isAGEPolicy(oid, format)`: for CAdES/XAdES true for OIDs `2.16.724.1.3.1.1.2.1.9` or `…1.8` with or without
the `urn:oid:` prefix (prefix compared case-insensitively); for PAdES only `…1.9`. The stored hash algorithm is the
normalised digest name (`SHA1`, `SHA-256`, `SHA-384`, `SHA-512`; `http://www.w3.org/2000/09/xmldsig#sha1` etc. are
normalised too). Note: the CAdES/PAdES AGE identifier is stored with the `urn:oid:` prefix (the signers accept it).

### 4.8 From preferences to signature parameters (`ExtraParamsHelper`)

Used whenever the GUI prepares a signature (single, multi-file). Only non-blank values are added. Policy sub-keys are
added only when the policy identifier is non-blank.

| Signer | extraParams produced |
|---|---|
| FacturaE | `policyIdentifier`, `policyIdentifierHash`, `policyIdentifierHashAlgorithm` ← `facturaePolicy*`; `signatureProductionCity/Province/PostalCode/Country` ← `facturaeSignatureProduction*`; `signerClaimedRoles` ← `facturaeSignerRole` |
| XAdES | `ignoreStyleSheets=false` (always); `policyIdentifier/Hash/HashAlgorithm/policyQualifier` ← `xadesPolicy*`; `signerClaimedRoles` ← `xadesSignerClaimedRole`; `signatureProduction*` ← `xadesSignatureProduction*`; `format` ← `xadesSignFormat` |
| PAdES | policy ← `padesPolicy*`; `signReason` ← `padesSignReason`; `signatureProductionCity` ← `padesSignProductionCity`; `signerContact` ← `padesSignerContact`; `signatureSubFilter` ← `padesBasicFormat`; `obfuscateCertText` = `padesObfuscateCertInfo` (always present, `"true"`/`"false"`) |
| CAdES **and any other signer (OOXML, ODF)** | policy ← `cadesPolicy*`; `mode` = `implicit`/`explicit` ← `cadesImplicitMode` (quirk: OOXML/ODF signers also receive these CAdES params) |

Additional parameters added by the sign screen (see §2/§3): `confirmDifferentProfile=true` for every GUI signature;
`certificationLevel` when the chosen level ≠ `0`; `allowSigningCertifiedPdfs=true` / `allowCosigningUnregisteredSignatures=true`
when the user confirms the corresponding warnings; visible signature `layer2*`, `signatureRotation`,
`signatureRubricImage` (§4.5.5). Digest: `signatureHashAlgorithm` (§4.5.2). Multisignature operation:
`cadesMultisign`/`xadesMultisign`. Validation of the loaded file: `allowShadowAttack` (§4.5.4) plus
`checkCertificates=true`.

The CLI (§5) and protocol invocations do **not** use these preferences (they take format/parameters from arguments or
the web request), except: `default.locale` (CLI messages), the keystore keys/filters for browser calls
(`useDefaultStoreInBrowserCalls`), `enabledJmulticard`, `vdiOptimization`, `enableProgressDialog`, proxy,
`secureConnections`/`secureDomainsList` and the trust-store admin keys.

### 4.9 The Preferences dialog

#### 4.9.1 Window

* Opened from menu Herramientas → `"Preferencias"` (Ctrl+P / mnemonic P) on Windows/Linux; from the application menu
  "Preferencias…" on macOS; and from the sign screen button `"Opciones Avanzadas"` (shown for files that are already
  CAdES/XAdES signatures) which opens the dialog directly on tab index 2 (CAdES) or 3 (XAdES).
* Modal `JDialog` titled `"Preferencias de configuración de firma electrónica"` (`MainMenu.24`), application icons,
  centred on the parent, disposed on close. Preferred size 600 × min(610, 0.8 × screen height); each tab scrolls
  vertically.
* Tabs (index, title, mnemonic, tooltip): 0 `"General"` (Alt+G); 1 `"Firmas PAdES (PDF)"` (F); 2 `"Firmas CAdES"` (E);
  3 `"Firmas XAdES"` (X); 4 `"Factura Electrónica"` (L); 5 `"Almacenes de claves"` (N).
* Buttons (right-aligned): `"Aplicar ahora"` (mnemonic p, initially disabled), `"Aceptar"` (A), `"Cancelar"` (C).
  Order: Windows/Linux `Aplicar ahora, Aceptar, Cancelar`; macOS `Cancelar, Aplicar ahora, Aceptar`.
  Accessible descriptions: `PreferencesPanel.35/.34/.32`.
* Esc closes the dialog (discarding unsaved control state) except on macOS.
* Any item change (checkbox, radio, combo) or key typed in metadata text fields enables "Aplicar ahora".

#### 4.9.2 Save (Aceptar / Aplicar ahora)

1. Validate XAdES policy → on error show `PreferencesPanel.6`, select tab 3, abort. Then PAdES (tab 1), then CAdES
   (tab 2).
2. Save tabs in this order: FacturaE, General, CAdES, PAdES, XAdES, Keystores (each through `put`/`putBoolean`, §4.3.2).
   General also applies `secureConnections` immediately (`HttpManager.setSecureConnections`).
3. `flush()`. "Aceptar" closes; "Aplicar ahora" disables itself.

#### 4.9.3 General tab actions

* `"Importar configuración"`: plain click → file chooser `"Seleccione el fichero de configuración"`, filter
  `"Configuraciones de Autofirma (*.afconfig)"` → §4.10.3. **Alt+click** → input dialog `"Seleccione la URL para descarga del fichero de preferencias"` / `"Importar configuración desde red"`, downloads the URL (normal TLS rules) and imports it the
  same way. Success: `"La configuración se ha importado correctamente."` (title `"Importación de la configuración"`) and
  the Preferences dialog closes. Errors: message `ImportPreferencesError.<code>` (§4.10.4) or
  `"Error importando la configuración desde red"`, title `"Error"`.
* `"Exportar configuración"`: save dialog `"Seleccione una ruta donde exportar el archivo de configuración"`, default
  name `exported_config.afconfig`, filter `*.afconfig` → §4.10.2; success `"La configuración se ha exportado correctamente."`
  (`"Exportación de la configuración"`).
* `"Restaurar configuración"`: confirm `"¿Desea restaurar la configuración general de la aplicación?"` (title
  `"Restaurar configuración"`) → deletes **all user keys of the main node** (`clearAll`) and the plain keys of the user
  keystore node (registered smart cards survive), reloads and closes the dialog. Note this also resets hidden user
  keys (language, visible-signature layout, proxy, secure domains, confirm-to-sign…).
* `"Configurar formatos"`, `"Dominios seguros"`, `"Configurar proxy"`, `"Certificados de confianza"` open the
  sub-dialogs of §4.5.3, §4.13, §4.12, §4.14.

#### 4.9.4 – 4.9.7 Format, policy, proxy, secure-domains sub-dialogs

Described in §4.5.3, §4.7.1, §4.12, §4.13. All of them persist on their own OK button.

#### 4.9.8 Per-tab "Restaurar configuración" buttons (immediate, no undo)

| Tab | Confirmation (es) | Keys removed from the user layer |
|---|---|---|
| PAdES | `"¿Desea restaurar la configuración de las firmas PAdES?"` | always: `padesSignReason`, `padesSignProductionCity`, `padesSignerContact`, `padesVisibleSignature`, `padesObfuscateCertInfo`, `padesVisibleStamp`; if not blocked also `padesBasicFormat`, the 4 `padesPolicy*`, `allowShadowAttack`, `allowCertifiedPDF`, `padesCertificationLevel` |
| CAdES | `"¿Desea restaurar la configuración de las firmas CAdES?"` | if not blocked: `cadesImplicitMode`, `cadesMultisign`, 4 `cadesPolicy*` |
| XAdES | `"¿Desea restaurar la configuración de las firmas XAdES?"` | always: 5 metadata keys; if not blocked: 4 `xadesPolicy*`, `xadesSignFormat` (forced to Detached if the resulting policy is AGE), `xadesMultisign` |
| FacturaE | `"¿Desea restaurar la configuración de las Facturas Electrónicas?"` | always: role + 4 metadata keys; if not blocked: `facturaEPolicy` + 4 policy keys |
| Keystores | `"¿Desea restaurar la configuración para los almacenes de claves?"` | deletes **all user-registered smart cards**, `defaultKeystore`, `useDefaultStoreInBrowserCalls`, `hideDnieStartScreen`, `showExpiredCerts`, `useOnlySignatureCertificates`, `useOnlyAliasCertificates`, `skipAuthCertDnie`; flushes (ignores the lock) |

#### 4.9.9 Keystores tab actions

* Default keystore combo: selecting `PKCS#12 / PFX` (by user action) opens the PKCS#12 file chooser; selecting
  `DNIe y tarjetas FNMT-TIF` immediately initialises the DNIe store (PIN dialogs) and on failure shows
  `"No se ha podido cargar el DNIe"` and reverts to index 0.
* Smart cards: combo (first item `"Seleccione una tarjeta"`), buttons `"Conectar"` (T), `"Agregar tarjeta"` (J),
  `"Modificar"` (I), `"Eliminar"` (M). Conectar/Modificar/Eliminar disabled until a card is selected; for
  system-defined cards only Conectar is enabled.
  * Agregar: dialog `"Agregar tarjeta como almacén de claves"` with `"Nombre de la tarjeta"` (text) and
    `"Controlador PKCS#11"` (read-only text + `"Examinar"`; file filter `*.dll` on Windows, `*.so, *.dylib` on macOS,
    `*.so` elsewhere, title `"Seleccionar controlador"`). Validation: both fields non-empty (`"Rellene todos los campos"`),
    name not already used (`"El nombre de tarjeta introducido ya se encuentra registrado…"`), library not already
    used (`"El controlador introducido ya se encuentra registrado…"`); on error the dialog reopens. On success the card
    is **immediately** stored in the user keystore node and added to both combos.
  * Modificar: same dialog pre-filled (title `"Modificar tarjeta"`); deletes the old entry and adds the new one
    (quirk: the duplicate-name check also matches the card's own current name, so renaming is required).
  * Eliminar: confirm `"¿Desea eliminar la tarjeta seleccionada?"` (title `"Eliminar tarjeta"`); deletes immediately.
  * Conectar: opens the PKCS#11 store (PIN prompt) and reports `"Conexión correcta con tarjeta inteligente."` or
    `"Error al conectar con tarjeta inteligente"`.

### 4.10 Import / export of configuration files (`.afconfig`)

#### 4.10.1 Format

An `.afconfig` file is an **Apple-style XML property list** (subset): root `<plist version="1.0">` containing a
single top-level `<dict>` of `<key>`/value pairs. Supported value elements when parsing: `string`, `true`, `false`,
`integer`, `real`, `date` (`yyyy-MM-dd'T'HH:mm:ss'Z'`), `data` (Base64), `array`, `dict`; but **only `string` and
boolean values are accepted for preference keys** (others → error 230303). The special key `smartcards` holds a
`<dict>` mapping card name → PKCS#11 library path. Unknown keys are imported verbatim (no key validation). The parser
takes the **first `dict` child of `plist`** and ignores other children (that is where an enveloped `ds:Signature` lives).

Example (the repository samples `configuracion*.afconfig` use the stale key `signatureAlgorithm` and non-matching
values such as `CAdes`/`PAdES-BES`; correct literals are shown here):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>preferencesBlocked</key><true/>
  <key>signatureHashAlgorithm</key><string>SHA512</string>
  <key>defaultSignatureFormatPdf</key><string>PAdES</string>
  <key>defaultSignatureFormatOoxml</key><string>OOXML (Office Open XML)</string>
  <key>xadesSignFormat</key><string>XAdES Detached</string>
  <key>xadesPolicyIdentifier</key><string>urn:oid:2.16.724.1.3.1.1.2.1.9</string>
  <key>xadesPolicyIdentifierHash</key><string>G7roucf600+f03r/o0bAOQ6WAs0=</string>
  <key>xadesPolicyIdentifierHashAlgorithm</key><string>SHA1</string>
  <key>xadesPolicyQualifier</key><string>https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf</string>
  <key>padesBasicFormat</key><string>ETSI.CAdES.detached</string>
  <key>cadesImplicitMode</key><true/>
  <key>facturaEPolicy</key><string>3.1</string>
  <key>omitAskOnClose</key><false/>
  <key>checkForUpdates</key><false/>
  <key>smartcards</key>
  <dict>
    <key>Tarjeta corporativa</key><string>C:\Windows\System32\corp-pkcs11.dll</string>
  </dict>
</dict>
</plist>
```

Gotchas: (1) the XML parser forbids DOCTYPE declarations (`disallow-doctype-decl`), so a plist carrying the usual
`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" …>` header is **rejected** (error 230302) in the current code;
(2) booleans may be written either as `<true/>`/`<false/>` or as `<string>true</string>` (both end up as the string
`true`).

#### 4.10.2 Export (`PreferencesPlistHandler.exportPreferencesToXml`)

1. Start with all keys of the effective **system** node (real or updated copy); then overlay all keys of the **user**
   node (user wins). Values exactly `true`/`false` become `<true/>`/`<false/>`, everything else `<string>`. Defaults
   and internal keys are not exported.
2. If any smart card is registered (user ∪ system, system wins on name clash) add `smartcards` → dict.
3. Output `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">` + dict + `</plist>` (no DOCTYPE, compact,
   UTF-8). Gotcha: `proxyPassword` is exported in its reversible ciphered form (§4.12).

#### 4.10.3 GUI import (`PreferencesPlistHandler.importPreferences(file|bytes, parent, blocked)`)

1. Parse securely (no DTD/DOCTYPE, no external entities). Read failure → 230301; not XML → 230302; other → 230300.
2. Signature check (`XAdESValidator.validate(doc, checkCertificates=true)`):
   * Look for every `Signature` element in namespace `http://www.w3.org/2000/09/xmldsig#` anywhere in the document. None
     → the file is **unsigned** (not an error).
   * For each signature: key taken from `KeyInfo` (`KeyValue` or first certificate of `X509Data`); the signature must
     validate (core validation, SignatureValue and every Reference; a custom URI dereferencer is installed for
     same-document references). The certificates in `X509Data` must be within their validity period
     (`checkValidity`) – expired/not-yet-valid → 522001 `"El certificado firmante del fichero de configuración no es válido"`.
     Any other failure (bad digest, no KeyInfo, no certificate) → 522002 `"La firma del fichero de configuración no es válida"`.
   * **No trust-chain validation** is done. Signer = first certificate of the first signature.
3. `requireSignedPrerefences` (internal admin key): intended to reject unsigned files with 522004
   `"No se permite la importación de ficheros de preferencias sin firmar"`. **Bug:** the Java condition is
   `required && signed` – it rejects *signed* files and accepts unsigned ones. Implement the intended behaviour
   (`required && unsigned → 522004`) and note the divergence.
4. If signed and `certHashToSignedPrerefences` is set: compute Base64(SHA-256(DER of signer cert)); mismatch → 522003
   `"El certificado firmante del fichero de configuración no está autorizado"`.
5. Confirmation (warning, Yes/No), title `"Importar configuración de firma"`, text: `"Si continua, se reemplazará la
   configuración actual con la indicada en el fichero, ¿Desea continuar? Si cancela la importación, no se aplicará
   ninguna configuración del fichero seleccionado."` followed by either `"El fichero de preferencias esta firmado
   digitalmente por: <CN>"` or `"El fichero de preferencias no esta firmado, no se hizo ningún cambio en la configuración"`
   (sic). No → nothing changes.
6. Yes → parse plist (230303 on failure). `smartcards` → registered into the **user** keystore node: cards whose library
   path is already registered (user or system) are skipped; name clashes get suffixes `-1`, `-2`… Then every value
   must be a non-null string/boolean (else 230303). Each key is written with `put`/`putBoolean` to the **user** layer
   (so values equal to system/default simply delete the user key), skipping protected keys when `blocked` (unreachable
   in practice). Existing user keys not present in the file are **kept** (merge, not replace, despite the dialog text).

#### 4.10.4 Error codes (`ConfiguratorErrorCode`, UI message key `ImportPreferencesError.<code>`)

| Code | Constant | Message (es, UI) |
|---|---|---|
| 230300 | `Internal.IMPORTING_PREFERENCES_ERROR` | `"Error desconocido importando las preferencias"` |
| 230301 | `Internal.CANT_READ_PREFERENCES_FILE` | `"No se pudo leer el fichero de preferencias"` |
| 230302 | `Internal.INVALID_XML_PREFERENCES_FILE` | `"El fichero de preferencias no es un XML válido"` |
| 230303 | `Internal.INVALID_FORMAT_PREFERENCES_FILE` | `"El fichero de preferencias no tiene un formato válido"` |
| 522001 | `Functional.INVALID_CERTIFICATE_SIGNER` | `"El certificado firmante del fichero de configuracióon no es válido"` (sic) |
| 522002 | `Functional.INVALID_PREFERENCES_FILE_SIGNATURE` | `"La firma del fichero de configuración no es válida"` |
| 522003 | `Functional.INVALID_PREFERENCES_FILE_SIGNER` | `"El certificado firmante del fichero de configuración no está autorizado"` |
| 522004 | `Functional.UNSIGNED_PREFERENCES_FILE` | `"No se permite la importación de ficheros de preferencias sin firmar"` |

#### 4.10.5 Producing a signed configuration file

Any XMLDSig/XAdES **enveloped** signature whose `ds:Signature` is a child of `<plist>` (after the `<dict>`), with
`Reference URI=""` + enveloped-signature transform and the signer certificate in `KeyInfo/X509Data`, is accepted – e.g.
signing the `.afconfig` with AutoFirma as "XAdES Enveloped". The admin pins it by setting
`certHashToSignedPrerefences` (system internal node) to Base64(SHA-256(cert DER)).

### 4.11 System configuration import and remote auto-update (`ConfigUpdaterManager`)

#### 4.11.1 Install-time import (`savePrefsConfigFile(path, allowUpdates)`, called by the configurator, §9)

1. Read `path`: if it starts with `https:` (case-insensitive) download it **with TLS validation disabled**
   (`DataDownloader.downloadData(url, false, ignoreSSL=true)`); otherwise read it as a local file.
2. `hash` = upper-case hex SHA-256 of the bytes.
3. `clearAllSystemPrefs()` then `importSystemPreferencesFromXml`: parse plist; `smartcards` → **replace** all system
   smart cards; remaining keys → `putSystemPref`/`putBooleanSystemPref` (booleans as `true`/`false`); flush. **No
   signature verification and no user confirmation** for system imports.
4. Internal node: `configFileUrl = path`; `allowUpdateConfig = true` only if `allowUpdates` and the path starts with
   `https://` (otherwise the key is removed); `configFileSHA256 = hash`; `configDate = today`; flush.
5. All errors are only logged (installation continues).

#### 4.11.2 Daily check at desktop start-up

Performed only when the app is launched as a desktop tool (not for protocol/CLI invocations), in a background thread:

```
needCheck = systemInternal.allowUpdateConfig == true            # read from the SYSTEM root only
            and internal.configFileUrl startsWith "https://"
            and (internal.configDate is null or today("YYYYMMdd") > internal.configDate)   # string compare
if needCheck:
    data = download(configFileUrl, ignoreSSL=true); on error: log and stop (date NOT updated)
    if hex(SHA-256(data)) != internal.configFileSHA256:
        clearAllSystemPrefs(); importSystemPreferencesFromXml(data); internal.configFileSHA256 = hash
    internal.configDate = today; flushSystemPrefs()
```

If the process cannot write the real system nodes, the values go to the user-root "updated" copies
(`…/ui/systempreferences`, `…/ui/internalpreferences`, `/es/gob/afirma/core/systemkeystores`), which are used as the
system layer on the next start (only while the real system node exists and `allowUpdateConfig` is true). New values
take effect at the **next** start (the running process already initialised its layers).

Security notes for the port: download with proper TLS validation, and optionally require a valid signature (§4.10.3)
on remote configuration as well.

### 4.12 Proxy settings

Dialog `"Configuración de proxy"` (`ProxyPanel`/`ProxyPanelHandler`), info text `"La configuración de proxy se aplica a HTTP, HTTPS, FTP y SOCKS."`:

* Radios: `"Sin proxy"` → `NONE`; `"Usar la configuración de proxy del sistema"` → `SYSTEM`;
  `"Configuración manual del proxy"` → `CUSTOM` (enables the manual panel).
* Manual panel: `"Host: "`, `"Puerto:"` (digits only, **max 4 characters** – ports > 9999 cannot be typed, quirk),
  `"Usuario:"`, `"Contraseña:"`, `"No usar proxy para las siguientes IP y direcciones de dominio:"` (text area, help
  `"Las direcciones se separan con comas (,) y se puede utilizar asterisco (*) al principio y fin de las direcciones como comodín."`),
  buttons `"Autodetectar"` (fills host/port from the OS/browser proxy for `https://firmaelectronica.gob.es/`, or warns
  `"No se han detectado proxies en el sistema"`) and `"Verificar conexión"` (HTTP proxy connection test to
  `https://firmaelectronica.gob.es/`; `"Conexión correcta"` / `"La configuración de proxy es errónea o no permite acceder a servicios externos."`).
* Load: `proxyType` (invalid → `NONE`); legacy: if the **user** layer has `proxySelected`, then `false` → `SYSTEM`,
  `true` with non-blank host → `CUSTOM`.
* Save (OK): for `CUSTOM` host must be non-blank (`"El host no es válido"`) and port non-empty (`"El puerto no es válido"`);
  then `proxyHost`, `proxyPort`, `proxyUsername` (removed if blank), `proxyPassword` (ciphered, removed if empty),
  `proxyExcludedUrls` (commas replaced by `|`, removed if blank). For `NONE`/`SYSTEM` those five keys are removed.
  Always: remove `proxySelected`, write `proxyType`, flush, and apply immediately (runtime behaviour in §1).
* **Password cipher** (`ProxyUtil.cipherPassword`): AES/CBC/PKCS5Padding, key = Base64-decode
  `3zevqLjBQTqWKCDEev3kNyjRWQpeuKe3xYlcdGmBYZE=` (32 bytes), IV = Base64-decode `NKAe+g8shVCYWEEhLNPU0A==`; plaintext =
  UTF-8 password; stored value = **URL-safe Base64** (`+`→`-`, `/`→`_`) of the ciphertext. Fallback (if AES fails):
  DES/ECB/NoPadding with key bytes of `8W{t2r,B`, zero-padded to 8-byte blocks, stored as `<padLen>.<urlsafe-b64>`.
  Decipher: try AES (after mapping `_`→`/`, `-`→`+`), else DES (`<n>.` prefix → strip `n` trailing bytes). This is
  obfuscation only (hard-coded key); the port should use the OS keyring and migrate legacy values.

### 4.13 Secure domains list

Dialog `"Listado de dominios seguros"`: text area plus explanations `"Se consideran dominios seguros todos aquellos en los que la conexión está cifrada con un certificado SSL reconocido internacionalmente, vigente y emitido para el dominio en cuestión. Adicionalmente, se considerarán dominios seguros todos aquellos recogidos en este listado."`
and `"Las direcciones se separan por comas (,) o saltos de línea y se pueden utilizar asteriscos (*) al principio y final de cada una de ellas como comodín."`.

* Load: stored commas shown as line breaks. Save: trim; replace `\r` and `\n` with `,` (quirk: CRLF yields `,,` →
  empty entries); empty → key removed; applied immediately (JVM property `secureDomainsList`) and flushed.
* Matching (`UrlHttpManagerImpl.checkIsSecureDomain`, against the URL host, case-sensitive, entries split on `,`):
  `*x*` → host contains `x`; `*x` → host ends with `x`; `x*` → host starts with `x`; otherwise exact equality. A match
  **disables TLS certificate validation** for that connection. Gotcha: an entry `*` (or `**`) matches every host.
* This list is unrelated to which web origins may invoke AutoFirma (that is not configurable here).

### 4.14 Personal trusted certificates

* Store: `~/.afirma/TrustedCertsKeystore.jks` (JKS, password `changeit`), one `trustedCertEntry` per certificate,
  alias = subject X.500 DN string (`"<DN> (1)"`, `"<DN> (2)"`… if taken); duplicates (same certificate) skipped.
  If the file exists but cannot be loaded the user is asked whether to delete and regenerate it
  (`"No se ha podido cargar el almacén de confianza de Autofirma. ¿Desea regenerarlo?"`).
* Dialog `"Certificados de confianza"`: table `"Certificados importados"` with columns `"Nombre"` (subject CN),
  `"Emitido por"` (issuer CN), `"Fecha de expiración"` (`dd-MM-yyyy`); buttons `"Importar..."`, `"Ver certificado"`
  (also double-click; opens the OS certificate viewer), `"Eliminar"` (confirm `"¿Está seguro de que quiere eliminar el certificado '<CN>'?"`).
* `"Importar certificados"` dialog: `"Importar certificado local"` (`"Examinar"`, multi-select `*.cer, *.cert, *.crt`,
  DER or PEM) and `"Importar certificado desde URL"` (`"URL"` field + `"Obtener certificado"`; `https://` is forced; the
  server chain is fetched – first with validation, retried without on handshake failure – and the **chain minus the
  leaf** is proposed, or the leaf if the chain has one element).
* Confirmation dialog: `"Se han cargado los siguientes certificados:"` table + `"Ver certificado"`, `"Omitir"` (remove a
  row), `"Importar certificados"`, `"Cerrar"`; import writes the JKS and reloads the TLS trust managers.
* TLS trust = JRE/OS trust ∪ personal store, only when `secureConnections=true` and `allowPersonalTruststore=true`.
* When an HTTPS connection fails because of an untrusted certificate and auto-import is allowed (§4.4.3), the user is
  asked (`"Verificación de dominio"`: `"Se ha tratado de conectar con el dominio <host> que presenta un certificado SSL que no es de confianza. ¿Desea importar este certificado a su almacén de confianza?"`).

### 4.15 Registered smart cards (`KeyStorePreferencesManager`)

* Stored as child nodes `1`, `2`, … (first free integer) under `/es/gob/afirma/core/keystores` (user) or the system
  equivalent; each child holds one entry `<card name>` = `<absolute PKCS#11 library path>`.
* Effective list = user ∪ system (system entries win on name clash in maps; in the UI system cards are flagged
  read-only). System cards come from the "updated" copy `/es/gob/afirma/core/systemkeystores` (user root) when it
  exists and `allowUpdateConfig` is true in the system internal node, else from the system root.
* Delete (user only) removes the child node whose single key equals the name.
* `smartcards` dict in `.afconfig`: user import merges (skips already registered libraries, renames clashes with
  `-N`); system import replaces all system cards.
* Registered cards appear in the default keystore combo and are opened as PKCS#11 stores with that library (§3).
* Quirk: when no system node existed, a *system* import writes the cards to `/es/gob/afirma/core/prefs`
  (`systemNodeForPackage`) which is **never read** – system smart cards from installer configs are lost in that case.

### 4.16 Keys read but not editable in the Preferences dialog

`preferencesBlocked`, `default.locale` (language menu), `checkJavaVersion`, `confirmToSign` (also editable),
`hideDnieStartScreen` (also from DNIe screen), the seven `pdf*` visible-signature keys (§4.5.5), `proxySelected`
(legacy), `requireSignedPrerefences`, `certHashToSignedPrerefences`, `allowPersonalTruststore`,
`allowAutoImportTrustedCerts`, `configFileUrl`, `allowUpdateConfig`, `configFileSHA256`, `configDate`, and the
auxiliary nodes of §4.2.1 (`lastCheckDate`, `currentDir`, `certView`, `useCacheDni`, `useCacheCeres`, plug-in keys).

### 4.17 Consolidated quirks and gotchas

1. User layer overrides system layer for all keys, including `preferencesBlocked` and trust-store admin keys (§4.4.5).
2. `requireSignedPrerefences` logic inverted (§4.10.3, step 3); key names misspelled `…Prerefences` (keep them).
3. Remote/installer configuration downloads ignore TLS validation and are never signature-checked (§4.11).
4. `configDate` uses Java pattern `YYYYMMdd` (week-based year): checks made between ~29–31 December may store next
   year's date, blocking further daily checks for up to a year. Use calendar year in the port (and accept the legacy
   value).
5. Shipped defaults: OOXML and ODF → **CAdES** (§4.6).
6. `allowShadowAttack=true` means "perform the PDF Shadow Attack check".
7. `SignPanel` (multi-file path) reads `padesVisibleSignature` where it should read `allowCertifiedPDF` to decide
   whether to apply `padesCertificationLevel`.
8. PAdES "Tipo por defecto" combo enabled when blocked (`setEnabled(isBlocked())`).
9. Formats sub-dialog: when blocked, combos are disabled but "Reestablecer" + OK still writes built-in defaults to the
   user layer, overriding the administrator's values.
10. XAdES custom policy identifiers must be OIDs although the label says URI; CAdES/PAdES "empty hash → download" path
    is effectively unusable because the identifier must be an OID.
11. FacturaE `facturaePolicyQualifier` is never sent; FacturaE 3.0 identifier contains spaces.
12. OOXML/ODF signers receive CAdES extraParams.
13. Sub-dialog/restore writes are not undone by "Cancelar" (§4.3.3).
14. `.afconfig` with DOCTYPE rejected (§4.10.1); repository sample files use stale key `signatureAlgorithm` and
    literal values (`CAdes`, `PAdES-BES`, `Política de Factura Electrónica 3.1`) that do not match stored literals.
15. Proxy port limited to 4 digits; proxy password reversible with a public key; exported in `.afconfig`.
16. Secure-domain `*` entry disables TLS validation for every host; CRLF produces empty entries.
17. Smart-card system import may write to an unread node (§4.15). Smart-card "Modificar" requires a new name.
18. `preferences.properties` contains dead keys `lastCheckDate`, `jmulticardCachePassword`.
19. "Restaurar configuración" (General) wipes every user key including language and proxy.

### 4.18 Parity notes for the Rust implementation

* Keep the exact key strings and literal values (they are part of the admin/`.afconfig` contract).
* Provide a read-only "Managed by your organisation" indicator per control when the value comes from a locked system
  layer (improves on the Java UX).
* Support `.afconfig` import (GUI, user layer, with signature/pinning checks) and system import (installer/CLI
  configurator flags, §9), export, and the remote daily update.
* Read legacy Java preference stores on first run (decode Windows escaping) and migrate user values.


## 5. Command line interface

This section specifies the console interface of AutoFirma (`CommandLineLauncher`, `CommandLineCommand`,
`CommandLineParameters`, `CommandLineMessages`, `CommandLineException`, `CommandLineParameterException`,
all in `afirma-simple/src/main/java/es/gob/afirma/standalone/`) plus the commands contributed by the hash
plugin (`createdigest`, `checkdigest`, see §7 for the hash engine itself).

Overall: the CLI has **6 built-in commands** (`sign`, `cosign`, `countersign`, `listaliases`, `verify`,
`batchsign`). It has no `massive`, `selectcert` or `-version` command. Plugins can add more commands; the
official hash plugin adds `createdigest` and `checkdigest`.

### 5.1 Entry points and how CLI mode is selected

#### 5.1.1 Through the normal application entry point (`SimpleAfirma.main`)

`SimpleAfirma.main(args)` is the entry point of `autofirma.jar` and `Autofirma.exe`. §1 specifies it fully.
Steps relevant to the CLI, in order:

1. `configureLog()`: optional file log and log level (§1).
2. The progress dialog manager is initialised. It shows nothing unless `args[0]` is an `afirma://` URL.
3. The default locale is set from preference `default.locale`, falling back to `es_ES` (§4, §11).
4. The look and feel is applied, because GUI dialogs may still appear in CLI mode.
5. Proxy settings are applied with `ProxyUtil.setProxySettings()` (§1, §4). A failure here is only logged in
   CLI mode, because the error dialog is shown only when there are no args.
6. The SSL context configuration task (`SSLContextConfigurationTask`) starts in a background thread.
7. **CLI mode** is entered when **any** of these holds:
   - there is at least one argument and `args[0].toLowerCase()` does **not** start with `afirma://`
     (`isUsingCommandLine`);
   - the JVM runs headless (system property `java.awt.headless=true`, `isHeadlessMode`). In that case even
     *no arguments* gives CLI mode, which prints the general help.
   When CLI mode is entered, `CommandLineLauncher.main(args)` is called and `SimpleAfirma.main` returns.
8. Fallback: if the GUI start later fails with `HeadlessException`, the request is reprocessed with
   `CommandLineLauncher.main(args)`.

Consequences:
- No single-instance check, update check, plugin-load error dialog or trust-store check runs in CLI mode.
  Plugins are still loaded, so that plugin commands work.
- **Gotcha:** a bare file path as the first argument (`autofirma /tmp/doc.pdf`) is **not** opened in the GUI.
  It is treated as an unknown command: the output is `Comando no reconocido: /tmp/doc.pdf` plus the general
  help, and the exit status is -1. Opening a file in the GUI must go through `sign -gui -i <file>` (this is
  what the Windows context menu does, §5.13). macOS has no alternative either: the launcher stub handles only
  `kAEGetURL` (afirma:// URLs) and `OSXHandler` registers no open-file handler, and the bundle declares no
  `CFBundleDocumentTypes` (§1.1, §1.16, §9.5.2).

#### 5.1.2 `CommandLineLauncher.main(args)`

1. Console logging is switched off so that it does not mix with command output. The level of the JUL loggers
   `java.util.prefs`, `es.gob.afirma` and `es.gob.jmulticard` is set to `OFF`, and
   `org.slf4j.simpleLogger.defaultLogLevel=off` is set.
   **Quirk:** these are logger levels, so they also silence the optional file log configured in §1.
2. `LookAndFeelManager.applyLookAndFeel()`.
3. The plugin manager is obtained (`SimpleAfirma.getPluginsManager()`, §7).
4. `processCommandLine(args)` runs (§5.3).

#### 5.1.3 Per-OS launchers

| OS | Console launcher | Notes |
|---|---|---|
| Windows | `AutofirmaCommandLine.exe`, installed next to `Autofirma.exe` in `%ProgramFiles%\Autofirma\Autofirma\` | A launch4j wrapper with `headerType=console`, `mainClass=es.gob.afirma.standalone.CommandLineLauncher`, JRE search path `./jre;%JAVA_HOME%;%PATH%`, JVM options `-Xms512m -Xmx8g` (files `AutofirmaCommandLine_launch4J_project_{32,64}.xml`). `Autofirma.exe` itself is a *GUI-subsystem* launcher (`headerType=gui`, splash `splash.bmp`, extra `-Djdk.tls.maxHandshakeMessageSize=65536`), so its stdout is not visible in a console. That is why a separate console exe exists. The installer adds the installation directory to the system `Path` (`autofirma-addpath.cmd`, see §9). **Gotcha:** `AutofirmaCommandLine.exe` calls `CommandLineLauncher.main` directly. It **skips** `SimpleAfirma.main`, so no proxy configuration, no SSL-context task and no file logging. |
| Linux | `/usr/bin/autofirma` (deb) | Shell script: `java -Djdk.tls.maxHandshakeMessageSize=65536 -jar /usr/lib/Autofirma/autofirma.jar "$@"`. It goes through `SimpleAfirma.main`. |
| macOS | `/Applications/Autofirma.app/Contents/MacOS/AutofirmaCommandLine` | A script inside the app bundle. It is documented in the bundled help page `LineaComandos.html` but not present in this repository (the macOS launcher is built outside it). The help advises single-quoting arguments that contain spaces. |

**Rust recommendation:** use one binary with a `cli` dispatcher. On Windows ship two PE images, one per
subsystem (`autofirma.exe` GUI and `autofirma-cli.exe` console), or have the GUI binary attach to the
parent console with `AttachConsole(ATTACH_PARENT_PROCESS)`. Keep the name `AutofirmaCommandLine.exe` as an
alias for scripts that depend on it.

### 5.2 Locale, output channel and exit status

- **Locale.** `processCommandLine` re-reads preference `default.locale` (§4). If it is empty or unset, the
  JVM/OS default locale is used. This differs from the GUI, which falls back to `es_ES`. The locale selects
  the `commandlinemessages_<ll>_<CC>.properties` bundle. Available bundles: `es_ES`, `en_US`, `ca_ES`,
  `gl_ES`, `eu_ES`, `va_ES` (§11). Imported language packs are also searched in the languages directory
  (`LanguageManager`, §11).
- **Message lookup quirks.** A key missing from the active bundle is rendered `!<key>!`.
  Example: the `en_US` bundle lacks `CommandLineLauncher.146`–`149`, and its `CommandLineLauncher.23`
  contains a literal `%0` ("…Priority over %0"). So the English help prints `… Priority over %0
  !CommandLineLauncher.146!`. The parameterised `getString(key, params…)` returns `!key!` whenever the
  primary bundle lacks the key, even when a fallback bundle has it (bug). Substitution replaces `%0`, `%1`, …
  literally; `null` parameters are skipped.
- **Output channel.** When the process has a console (`System.console() != null`), output goes to the console
  writer. Otherwise it goes to `System.out`, encoded in the platform default charset.
  **Everything goes to stdout, including errors and help.** stderr is never used. Each printed message is
  followed by a single `\n`.
- **Exit status.**
  | Situation | Status |
  |---|---|
  | General help (`-help` or no args) | `0` |
  | Command help (`<cmd> -help`) | `0` |
  | Successful `sign`/`cosign`/`countersign`/`listaliases`/`verify`/plugin command with a non-null response | `0`, via `System.exit(0)` after printing |
  | `sign -gui`, `verify -gui` | No exit is forced. The JVM stays alive with the GUI, and the status is whatever the GUI exits with (normally `0`, §2). |
  | `batchsign` (any outcome except parameter, filter or alias errors and unexpected runtime errors) | **No message is printed and `System.exit` is not called.** The process ends when its non-daemon threads end, so the status is `0`, even after a keystore, network or server error (bug, see §5.9.6). |
  | Any error handled in §5.11 | `-1` (`STATUS_ERROR`). The shell sees `255` on POSIX and `4294967295`/`-1` on Windows. |
  | Hash plugin `-gui` modes | `Runtime.halt(0)` once the GUI flow returns (§7). |

### 5.3 Top-level grammar and dispatch (`processCommandLine`)

```
<launcher> -help
<launcher> <command> -help
<launcher> <command> [options...]
```

Algorithm:

1. If `args` is empty or `args[0]` equals `-help` (case-insensitive): print the **general help** (§5.3.1) and
   exit `0`.
2. `command := args[0].toLowerCase()`. Commands are therefore **case-insensitive**.
3. `needXml :=` some `args[i]` with `i ≥ 1` equals `-xml`, case-insensitive. This flag only decides whether
   *error* messages are wrapped in XML (§5.10). The actual `-xml` option is parsed case-sensitively.
4. If `command` is a built-in (`listaliases`, `sign`, `cosign`, `countersign`, `verify`, `batchsign`), run
   `processCommand` (§5.9).
5. Otherwise look for a plugin command. Loaded plugins are iterated, and only those whose `plugin.json`
   declares permission `COMMANDS` are considered. The first plugin command whose name equals `args[0]`
   (case-insensitive) is used. Its `PluginCommandAction` class is instantiated and `start(args)` is called;
   `start` strips the leading command token before calling `process`. The returned string is the response.
6. Otherwise throw `UnsupportedOperationException(generalHelp("Comando no reconocido: " + args[0]))`.
   Status `-1`.
7. Print the response. If the response is non-null, `System.exit(0)`.
8. In `processCommand`: if `args.length > 1` and `args[1]` equals `-help` (case-insensitive), return the
   command help (§5.3.2) as the response. Otherwise parse the parameters (§5.4) and run the command.

#### 5.3.1 General help text (exact construction)

`<app>` is `DesktopUtil.getApplicationFilename()`: the file name of the JAR/EXE the code was loaded from
(URL-decoded), e.g. `autofirma.jar` or `AutofirmaCommandLine.exe`, falling back to `Autofirma`. Below, `\t`
is a TAB and `\n` a newline. Message keys are shown with their Spanish text.

```
Herramienta de firma de documentos.\n\n                         (CommandLineLauncher.34, only when there is no error message;
                                                                otherwise "<error message>\n" replaces this line)
Sintaxis: <app> cmd [opciones...]\n\n                          (.7 ": " app " cmd [" .140 "...]")
Comandos cmd:\n\n                                              (.33 " cmd:")
  sign\t\t (firma de fichero)\n                                (.8)
  cosign\t (cofirma de fichero)\n                              (.9)
  countersign\t (contrafirma de fichero)\n                     (.10)
  listaliases\t (lista los alias disponibles en el almacen)\n  (.11)
  verify\t (abre un panel con la informacion de validacion de una firma o certificado)\n   (.29)
  batchsign\t (firma/multifirma de lotes de ficheros)\n\n     (.69)
[Comandos agregados a traves de plugins:\n\n                  (.126, only if at least one plugin command exists)
  <name>\t (<description from plugin.json>)\n   ... one line per plugin command ...
  \n]
Utilice "<app> cmd -help" para ver la sintaxis del comando "cmd"   (.30 with %0=<app>)
```

- If loading the plugin commands throws, the text `No se pudieron cargar los comandos de los plugins
  instalados.` (.125) is inserted with no trailing newline (quirk).
- Plugin commands are listed **without** the `COMMANDS` permission check, but they can only be executed with
  it (quirk).
- With the hash plugin installed, the extra lines are `createdigest (Creación de huellas digitales con
  interfaz gráfica)` and `checkdigest (Comprobación de huellas digitales con interfaz gráfica)`. In the
  repository `plugin.json` these strings carry mis-encoded accents (`Creaci�n`), so the Rust build should
  store them as UTF-8.

Rendered example, from the bundled help page:

```
Herramienta de firma de documentos.
Sintaxis: Autofirma cmd [options...]
Comandos cmd:
  sign           (firma de fichero)
  cosign         (cofirma de fichero)
  countersign    (contrafirma de fichero)
  listaliases    (lista los alias disponibles en el almacen)
  verify         (abre un panel con la informacion de validacion de una firma o certificado)
  batchsign      (firma/multifirma de lotes de ficheros)
  createdigest   (creacion de huella digitales con interfaz grafica)
  checkdigest    (comprobacion de huella digitales con interfaz grafica)
Utilice "Autofirma cmd -help" para ver la sintaxis del comando "cmd"
```

#### 5.3.2 Per-command help texts (exact construction)

Every command help starts with `[<error message>\n]` (when it is printed because of a parameter error),
followed by `Sintaxis: <app> <op> [opciones...]\n\nOpciones:\n`. The option lines are then:

**`sign`, `cosign`, `countersign`** (identical list; only `<op>` changes):
```
  -gui\t\t\t (Realiza la operacion con entorno grafico. Tiene prioridad sobre -certgui)\n   (.23 + " " + .146(%0=-certgui))
  -certgui\t\t (Usa un dialogo grafico para la seleccion del certificado de firma)\n          (.76)
  -i inputfile\t\t (Ruta del fichero de entrada)\n                                            (.13)
  -o outputfile\t\t (Ruta del fichero de salida)\n                                           (.14)
  -algorithm algo\t (Algoritmo de firma)\n                                                  (.20)
  \t sha1\t\t (Firma con algoritmo de huella SHA-1 (No recomendado))\n                     (.142)
  \t sha256\t\t (Firma con algoritmo de huella SHA-256)\n                                   (.143)
  \t sha384\t\t (Firma con algoritmo de huella SHA-384)\n                                   (.144)
  \t sha512\t\t (Firma con algoritmo de huella SHA-512 (Por defecto))\n                     (.145)
  -format\t\t (Establece el formato de firma)\n                                            (.32)
  \t auto\t\t (Seleccion de formato en base al fichero de entrada)\n                      (.42)
  \t cades\t\t (Formato CAdES)\n                                                         (.43)
  \t pades\t\t (Formato PAdES)\n                                                         (.44)
  \t xades\t\t (Formato XAdES)\n                                                         (.45)
  \t facturae\t (Firma de factura electronica)\n                                         (.46)
  \t ooxml\t\t (Formato OOXML)\n                                                         (.72)
  \t odf\t\t (Formato ODF)\n                                                             (.73)
  -config extraParams\t (Properties en texto plano con la configuracion de la operacion)\n   (.27)
  -store\t\t (Establece el almacen de claves. Por defecto, el del sistema)\n               (.31)
  \t auto\t\t (Almacen de claves del sistema)\n                                          (.36)
  \t windows\t (Almacen de claves de Windows)\n                                          (.37)
  \t mac\t\t (Almacen de claves de macOS)\n                                              (.38)
  \t mozilla\t (Almacen de claves de Mozilla Firefox)\n                                  (.39)
  \t dni\t\t (DNI electronico)\n                                                         (.40)
  \t pkcs12:p12file\t (Almacen PKCS#12. "p12file" es la ruta del almacen)\n               (.41)
  \t pkcs11:p11file\t (Almacen PKCS#11. "p11file" es la ruta del controlador)\n           (.47)
  -password password\t (Establece la contrasena del almacen)\n                              (.12)
  -alias alias\t\t (Alias del certificado de firma)\n                                       (.16)
  -filter filter\t (Filtro para seleccionar el certificado de firma)\n                     (.66)
  -xml\t\t\t (Formatea la respuesta como XML)                                                (.18)
```

**`batchsign`:**
```
  -i inputfile\t\t (Ruta del fichero de configuracion de la operacion)\n        (.62)
  -o outputfile\t\t (Ruta del fichero con el XML resultado de la operacion)\n   (.63)
  -store ... (same 7 store lines as above, including pkcs11)
  -password password\t (...)\n
  -alias alias\t\t (...)\n
  -filter filter\t (...)\n
  -preurl url\t\t (URL del servicio externo de prefirma)\n                     (.64)
  -posturl url\t\t (URL del servicio externo de postfirma)\n                   (.65)
  -xml\t\t\t (Formatea la respuesta como XML)
```
`-config` is accepted and used by `batchsign` but is missing from its help.

**`verify`:**
```
  -gui \t\t (Realiza la operacion con entorno grafico.)\n   (.23 only)
  -i inputfile\t (Ruta del fichero de entrada)              (.13)
```

**`listaliases`:**
```
  -store ... (auto, windows, mac, mozilla, dni, pkcs12:p12file; pkcs11 is NOT listed but IS accepted)
  -password password\t (Establece la contrasena del almacen)\n
  -xml\t\t\t (Formatea la respuesta como XML)
```

Rendered example of `sign -help`, from the bundled help (older version, without the `ooxml`, `odf` and
`sha*` lines):
```
Sintaxis: Autofirma sign [opciones...]
Opciones:
  -gui                   (Realiza la operacion con entorno grafico. Tiene prioridad sobre -certgui)
  -certgui               (Usa un dialogo grafico para la seleccion del certificado de firma)
  -i inputfile           (Ruta del fichero de entrada)
  -o outputfile          (Ruta del fichero de salida)
  -algorithm algo        (Algoritmo de firma)
  -format                (Establece el formato de firma)
         auto            (Seleccion de formato en base al fichero de entrada)
         ...
```

### 5.4 Option parser (`CommandLineParameters`)

#### 5.4.1 General rules

- Options are matched **case-sensitively** and **exactly**: `-i` works, `-I` does not.
- Every built-in command has `mainFileNeeded=false`, so option parsing starts at `args[1]`. The positional
  "main file" branch exists only for plugins.
- A value-taking option consumes the **next token unconditionally**, even if it starts with `-`. If the
  option is the last token, a "value missing" error is raised (key in the table below).
- A repeated option raises `Parametro duplicado: <opt>` (.26). Boolean flags may be repeated.
- An unknown token raises `No se reconoce el parametro <tok>` (.25).
- `-alias` and `-filter` are mutually exclusive: `Las opciones '-alias' y '-filter' son excluyentes` (.28),
  raised when the second of the two is seen.
- Every exception raised while parsing carries a `usingGui` flag equal to "has `-gui` been seen **so far**".
  When the flag is true, an error dialog is also shown (§5.12). **Quirk:** it depends on the order of the
  options.
- After the loop, `checkParams()` validates, in this order:
  1. `-format` (lower-cased) is in `{xades, cades, pades, facturae, ooxml, odf, auto}`; otherwise
     `Formato de firma no soportado: <value>` (.4). This is a parameter error, so the syntax help is printed.
  2. `-hformat` (lower-cased) is in `{hex, bin, b64, xml, txt}`; otherwise .89. Parameter error.
  3. `-preurl` and `-posturl` must parse as `java.net.URL`; otherwise
     `La direccion indicada ('<v>') debe ser una URL valida: <exception>` (.59). Parameter error.
  4. `-i`: the file must exist (.0 `El fichero de entrada no existe: <v>`) and be readable (.1). These are
     plain errors: no syntax help.
  5. `-o`: if the path has a parent directory, the parent must be writable (.3 `No hay permisos de escritura
     en el directorio especificado para el fichero de salida: <v>`). The file itself may not exist yet and is
     overwritten without asking.
- **Tilde expansion** (Unix only, for `-i` and `-o`): when the value starts with `~`, the path becomes
  `new File(userHome, value.substring(1))`. So `~/a.pdf` resolves to `$HOME/a.pdf`. **Quirk:** `~bob/x`
  resolves to `$HOME/bob/x`.

#### 5.4.2 Option table (built-in commands)

| Option | Value | Used by | Default | Missing-value error | Notes |
|---|---|---|---|---|---|
| `-i` | path | sign, cosign, countersign, verify, batchsign | none | .74 `No se ha indicado fichero de entrada` | Required by all of these; when absent the command raises .5 `No se ha especificado un fichero de entrada`. For cosign and countersign the input is the existing signature. For batchsign it is the batch XML. |
| `-o` | path | sign, cosign, countersign, batchsign | none | .75 | Required unless `-xml` is given (.19 `No se ha indicado un fichero de salida`). Overwrites silently. |
| `-format` | `auto`\|`cades`\|`xades`\|`pades`\|`facturae`\|`ooxml`\|`odf` (case-insensitive) | sign, cosign, countersign | `auto` | .138 | See §5.8. |
| `-algorithm` | digest name | sign, cosign, countersign (and `-gui`) | `sha512` | .132 | See §5.8. **Not** taken from preferences. |
| `-config` | properties text | sign, cosign, countersign, batchsign | none | .134 | See §5.7. |
| `-store` | see §5.5 | sign, cosign, countersign, listaliases, batchsign | `auto` | .130 | |
| `-password` | text | same as `-store` | none | .135 | Keystore password, also used as the private-key entry password. Without it, sign uses the dummy entry password `"dummy"`. |
| `-alias` | alias | sign, cosign, countersign, batchsign | none | .136 | Exactly as listed by `listaliases`. |
| `-filter` | filter expression | sign, cosign, countersign, batchsign | none | .137 | See §5.6. |
| `-certgui` | flag | sign, cosign, countersign | off | | Graphic certificate chooser (§5.6). Ignored by batchsign. |
| `-gui` | flag | sign, verify | off | | Opens the GUI (§5.9.2, §5.9.4). Accepted but ignored by cosign, countersign, batchsign and listaliases. |
| `-xml` | flag | all built-ins | off | | XML response (§5.10). `verify` ignores it and always answers in plain text. |
| `-preurl` | URL | batchsign | none | .128 | |
| `-posturl` | URL | batchsign | none | .129 | |
| `-operation` | text | **none** | `sign` | .131 | Legacy massive-operation option: parsed, never used. |
| `-hformat` | `hex`\|`b64`\|`bin`\|`txt`\|`xml` | **none** | | .139 | Legacy, validated but unused by built-ins. The hash plugin has its own parser. |
| `-halgorithm` | text | **none** | | .133 | Legacy, unused. |
| `-r` | flag | **none** | | | Legacy, unused. |

`-help` anywhere other than `args[0]` or `args[1]` is an unknown parameter.

### 5.5 Keystore selection (`-store`)

`getKsm(storeType, password)` maps `-store` to a keystore type. The password callback is
`CachePasswordCallback(password)` when `-password` is given. Otherwise it is `null`, so the type's default
callback applies, and that may be a **GUI password prompt**. The keystore types are specified in the keystore
spec.

| `-store` value (exact, case-sensitive) | Keystore | Notes |
|---|---|---|
| absent or `auto` | macOS: Apple Keychain (`APPLE`); Windows: CAPI `WINDOWS`; other OSes: **shared system NSS DB** (`SHARED_NSS`, `~/.pki/nssdb`) | On Linux, `auto` is **not** Firefox. Use `mozilla` for Firefox. |
| `windows` | Windows CAPI store (`WINDOWS`) | |
| `mac` | Apple Keychain (`APPLE`) | |
| `mozilla` | Firefox/NSS unified store (`MOZ_UNI`) | May prompt for the NSS master password through the GUI. |
| `dni` or `dnie` | DNIe through the built-in Java driver (`DNIEJAVA`, JMulticard) | The PIN is asked through the GUI when signing. |
| `pkcs12:<path>` | PKCS#12 file (`PKCS12`) | The path is cleaned (trimmed, `"` and `'` removed, canonicalised) for the existence and readability checks, but the **raw, uncleaned** string is what gets passed to the keystore (quirk). Errors: `El fichero PKCS#12 indicado no existe: <p>` and `No se tienen permisos de lectura para el fichero PKCS#12 indicado: <p>` (hard-coded Spanish, raised as `IOException`). |
| `pkcs11:<path>` | PKCS#11 module (`PKCS11`) | The cleaned, canonical path is passed. Errors: `La biblioteca PKCS#11 indicada no existe: <p>` and `No se tienen permisos de lectura para la biblioteca PKCS#11 indicada: <p>`. |
| anything else | | Parameter error `Tipo de almacen desconocido: <v>` (.48). |

The keystore is opened with description `"CommandLine"`. A `KeystoreAlternativeException` is reported as
`El almacen de claves seleccionado no esta disponible: <msg>` (.49).

### 5.6 Certificate selection (`-alias`, `-filter`, `-certgui`)

Without `-certgui`, sign, cosign, countersign and batchsign require `-alias` or `-filter`. Otherwise:
`Se tiene que especificar un alias o un filtro para la seleccion del certificado de firma` (.17).

- **`-alias A`**: uses entry `A`. If the entry is missing or null:
  - sign: `No se hay ninguna entrada en el almacen con el alias indicado: A` (.148);
  - batchsign: `No se ha encontrado ninguna entrada en el almacen con el alias 'A', puede listar las entradas
    actuales con el comando "listaliases"` (.61).
  If the private key cannot be obtained: .147 `No se ha podido obtener la referencia a la clave privada`.
- **`-filter F`** (no `-certgui`): builds `Properties{filters=F}` and calls `CertFilterManager`.
  - `F` is **one** filter expression. Sub-filters inside it are separated by `;` and combined with **AND**.
  - Supported tokens (case-insensitive prefixes; their semantics are in the keystore/filters spec):
    `dnie:`, `ssl:<serial>`, `qualified:<serial>`, `signingcert:`, `authcert:`, `nonexpired:`, `sscd:`,
    `subject.rfc2254:<ldap-filter>`, `subject.contains:<text>`, `issuer.rfc2254:<ldap-filter>`,
    `issuer.rfc2254.recurse:<ldap-filter>`, `issuer.contains:<text>`, `thumbprint:<algo>:<hex>`,
    `policyid:<oids>`, `pseudonym:<only|andothers>`, `encodedcert:<b64>`,
    `keyusage.{digitalsignature,nonrepudiation,keyencipherment,dataencipherment,keyagreement,keycertsign,crlsign,encipheronly,decipheronly}:<true|false|null>`,
    and the bare token `disableopeningexternalstores`.
  - The filter is applied to every alias of the store. The CLI requires **exactly one** match. No match gives
    `No se han encontrado certificados que se ajusten al filtro establecido` (.52). More than one gives
    `Se ha encontrado mas de un certificado a partir del fitro establecido` (.53, typo as in the original).
  - When a filter is given, no implicit "non-expired" filter is added.
- **`-certgui`** (sign, cosign, countersign only; `-gui` takes precedence because sign with `-gui` never gets
  here):
  1. The certificate-filter properties are taken from `-config` (keys `filter`, `filters`,
     `filters.1..n`, `headless`, `mandatoryCertSelection`). If `-filter` is given, it is put as `filters`
     and overrides.
  2. `CertFilterManager` builds the filter list. When no filters are defined at all, it adds
     "hide expired certificates" (`ExpiredCertificateFilter(false)`).
  3. The modal certificate selection dialog opens (§3). It shows only entries with a private key, shows
     expired certificates (the dialog flag `showExpired=true`, while the filter list may still hide them),
     does not warn about expired certificates, and is not mandatory. Opening external stores from the dialog
     is allowed unless the `disableopeningexternalstores` token was given.
  4. The chosen certificate context may come from a **different** keystore than `-store`, because the user
     can switch stores in the dialog; that store is then used.
  5. Cancelling raises `AOCancelledOperationException`. It ends up as the generic error
     `Error no reconocido: <msg>` with status -1.

### 5.7 `-config` extra parameters

The value is a Java-properties-like text with the format-specific signer options (`mode`, `policyIdentifier`,
`signaturePositionOnPageLowerLeftX`, `headless`, `filters`, …). The option catalogue per format is in the
signature-format specs. The CLI implements two different parsers.

**Parser A, non-GUI** (`buildProperties`; used by sign, cosign, countersign and batchsign):
1. `s := value.trim()`.
2. Split `s` on the **literal two-character sequence `\n`** (backslash followed by `n`), **not** on real
   newlines. On a shell this means `-config "a=1\nb=2"` with a literal backslash.
3. For every piece except the last: `kv := piece.trim()`. If `kv` is non-empty and does not start with `#`:
   `key = kv[0 .. indexOf('=')]` (**not trimmed**) and `value = kv[indexOf('=')+1 ..]` (not trimmed).
4. The last piece is always processed, even if it starts with `#`: key and value are taken around its first
   `=` and **both trimmed**.
5. Quirks: a piece with no `=` throws `StringIndexOutOfBoundsException`, reported as the generic error.
   Spaces around `=` stay in the key and value, except in the last piece. Real newlines inside a value are
   kept.

**Parser B, GUI** (`loadSignConfig` for `sign -gui`): split on real `\n` characters; trim each line; skip
lines without `=` at position > 0 and lines starting with `#`; key and value are trimmed.

**Rust recommendation:** accept both `\n` escapes and real newlines, trim keys and values, ignore blank and
`#` lines, and reject lines without `=` with a clear error.

Special keys interpreted by the CLI itself:
- `target`: countersign target. `tree` (case-insensitive) gives `CounterSignTarget.TREE`; anything else or
  absent gives `LEAFS`. The key is also passed on to the signer.
- `filter`, `filters`, `filters.N`, `headless`, `mandatoryCertSelection`: only for `-certgui` (§5.6).
- `headless=true` stops the signers from opening confirmation and password dialogs (§5.12). The CLI does
  **not** set it automatically.

Example (from `SignFromCommandLineTest`, visible PAdES):
```
-config "signaturePositionOnPageLowerLeftX=100\nsignaturePositionOnPageLowerLeftY=100\nsignaturePositionOnPageUpperRightX=200\nsignaturePositionOnPageUpperRightY=200\nsignaturePage=1"
```
Other documented example: `-config "format=XAdES Enveloping\nsignerClaimedRoles=Director\nxadesNamespace=http://uri.etsi.org/01903/v1.4.1#"`.

### 5.8 Format and algorithm resolution

**Format → signer** (`getSigner`):

| `-format` | Signer (format spec) |
|---|---|
| `cades` | CAdES (`AOCAdESSigner`) |
| `xades` | XAdES (`AOXAdESSigner`) |
| `pades` | PAdES (`AOPDFSigner`) |
| `facturae` | FacturaE (`AOFacturaESigner`) |
| `ooxml` | OOXML (`AOOOXMLSigner`) |
| `odf` | ODF (`AOODFSigner`) |
| `auto` (default) | Chosen from the input bytes with `selectFormatByData` |

`selectFormatByData(data)`: `ext := MimeHelper(data).getExtension()`.
- `pdf` → `pades`
- `xml` → `xades`
- anything else → `cades`

OOXML and ODF auto-detection exist in the code but are commented out. FacturaE is **never** auto-selected,
because an invoice is XML and therefore goes to XAdES. This differs from the GUI, which uses
`DataAnalizerUtil` and the per-type preferences (§2, §4).

If the signer supports context configuration (`AOConfigurableContext`), it is put in **non-secure mode**
(`setSecureMode(false)`). This lets the signer load resources from local file paths given in the extra
params, e.g. `signatureRubricImage=C:/…/Rubrica.png`, external XSL or policy files. The Rust CLI must allow
file-path-valued options in the same way (but see §5.15).

**Algorithm.** The default is `sha512`. Help lists `sha1`, `sha256`, `sha384` and `sha512`; any spelling
accepted by `AOSignConstants.getDigestAlgorithmName` also works (case-insensitive `SHA1`/`SHA-1`/`SHA`,
`SHA256`/`SHA-256`, OIDs, XMLDSig URIs, or a full `SHA256withRSA`).
`composeSignatureAlgorithmName(digest, keyAlgorithm)` builds the signature algorithm as the digest name
without `-`, followed by `withRSA` for RSA keys, `withDSA` for DSA keys and `withECDSA` for keys whose
algorithm starts with `EC`. Example: `SHA512withRSA`. Any other key type gives
`El tipo de clave del certificado no esta soportado: <type>` (.141), a parameter error.
An unknown digest name passes through unchanged and makes the signer fail later.

### 5.9 Commands

#### 5.9.1 `sign`, `cosign`, `countersign` (non-GUI)

```
<launcher> sign        -i <in> (-o <out> | -xml) (-alias <a> | -filter <f> | -certgui) [-store <s>] [-password <p>]
                       [-format <fmt>] [-algorithm <alg>] [-config <props>] [-xml]
<launcher> cosign      ... same ...      (-i is the existing signature)
<launcher> countersign ... same ...      (-i is the existing signature; target via -config "target=tree")
```

Steps (`signByCommandLine` + `sign`):
1. Validate: `-i` present (.5), certificate selection present (.17), and `-o` or `-xml` present (.19). These
   are parameter errors: the message is printed followed by the command help.
2. Open the keystore (§5.5) and select the certificate (§5.6).
3. Set the entry password callback to `-password`, or `"dummy"` when absent. Get the `PrivateKeyEntry`
   (errors .147/.148).
4. Read the whole input file. On error: `No se ha podido leer el fichero de entrada: <abs path>`.
5. Resolve the format (§5.8), build the extra params (§5.7), and compose the signature algorithm from the key
   algorithm (§5.8).
6. Run the operation:
   - `sign` → `signer.sign(data, alg, key, chain, xp)`;
   - `cosign` → `signer.cosign(data, alg, key, chain, xp)`, where the data is the existing signature (the
     signer extracts the content if it is implicit);
   - `countersign` → `signer.countersign(data, alg, target, null, key, chain, xp)`, with `target` from
     `xp.target` (§5.7).
7. **PAdES visible-signature fallback.** If the signer throws `InvalidSignaturePositionException` or
   `IncorrectPageException`, the operation is retried once as an invisible signature. The retry removes every
   `-config` line containing `signaturePage`, `signaturePages` or one of the four
   `signaturePositionOnPage{Lower,Upper}{Left,Right}{X,Y}` keys, and re-enters step 3 using the composed
   signature algorithm as the algorithm. No warning is printed.
   **Quirk:** the kept lines are concatenated onto a `null` string, so the first kept key gets a `null`
   prefix and is effectively lost.
8. Any other signer exception becomes `CommandLineException(.149 "Error en la operacion de firma", cause)`.
   The printed message is the **cause's** message (§5.11).
9. If `-o` is given, write the bytes to the file, overwriting it. On error: .21
   `No se ha podido escribir en el fichero de salida: <abs path>`.
10. Response:
    - plain text: `La operacion ha terminado correctamente ` (.22, **with a trailing space**);
    - `-xml`: §5.10, including `<sign>` (Base64 signature) only when `-o` was **not** given.

Preferences are **not** consulted by non-GUI signing. Format, algorithm, policies, PAdES options and so on
all come from the CLI options and `-config` only.

#### 5.9.2 `sign -gui`

```
<launcher> sign -gui -i <file> [-format <fmt>] [-algorithm <alg>] [-config <props>]
```
This is what the Windows Explorer entry "Firmar con Autofirma" runs (§5.13).
1. If `-i` is missing: an error dialog (title .127 `Error en los parámetros de entrada`, message .5) is
   shown, the same text is printed, and the status is -1.
2. `loadSignConfig` builds a `SignOperationConfig`:
   - crypto operation `SIGN`. The code would map cosign to `COSIGN` and countersign to
     `COUNTERSIGN_LEAFS`, but those commands never use `-gui`.
   - **Format, actual behaviour (bug):** when `-format` is **not** `auto`, the requested value is ignored.
     The input file is read and the signer is chosen with `selectFormatByData`, so only PAdES, XAdES or CAdES
     are possible. When `-format` is `auto` (the default), no signer is set, and the GUI later picks the
     preference default for the detected file type (§2, §4).
   - extra params parsed with parser B (§5.7);
   - digest algorithm `getDigestAlgorithmName(-algorithm)`. Because `-algorithm` defaults to `sha512`, GUI
     signing launched this way **always uses SHA-512 unless `-algorithm` is given**, overriding the
     preference `signatureHashAlgorithm` (default SHA256).
3. `new SimpleAfirma().initGUI(file, config)` opens the main window with the file preloaded on the sign
   screen. No DNIe wait screen is shown. Then the default keystore loads (§2).
4. **Bug / Gotcha.** When the sign screen prepares the file with an externally given config, it starts from
   an empty extra-params object (`SignPanel.configureDataSigner(newConfig, config, data)`):
   - the `-config` values **and** the per-format preference extra params (`ExtraParamsHelper`) are both
     dropped;
   - only `confirmDifferentProfile=true` is set.
   So signatures started from the Explorer context menu do not apply the XAdES, CAdES or PAdES preference
   options (policy, packaging, etc.) the way a signature started from the main window does. The Rust
   implementation should decide whether to keep this. The recommendation is to apply the preferences, then
   the CLI overrides.
5. No exit is forced. The process lives until the window is closed.
6. Unlike a normal GUI start, there is no single-instance check, no update check and no plugin-error dialog.

#### 5.9.3 `verify` (console)

```
<launcher> verify -i <signature-or-signed-file>
```
1. `-i` is required (.5, parameter error). The file is read; on failure:
   `No se ha podido leer el fichero de entrada: <path>`.
2. `SignValiderFactory.getSignValider(bytes)` picks a validator from the data, specified in the validation
   spec. Then:
   - when a validator exists: `validityList = validator.validate(bytes)`, with default validation
     parameters;
   - when there is no validator and the data is a signed ODF: one entry `UNKNOWN` / `ODF_UNKOWN_VALIDITY`;
   - when there is no validator and the data is a signed OOXML: one entry `UNKNOWN` /
     `OOXML_UNKOWN_VALIDITY`;
   - when the list is still empty: one entry `KO` / `UNKOWN_SIGNATURE_FORMAT`;
   - any exception becomes `CommandLineException("Error en la validacion de la firma", e)`, which prints
     `e.getMessage()` with status -1.
3. **Output:** one line per `SignValidity`, each terminated by `\n` (plus the final `\n` added by the
   printer). Status `0` **whatever the validity**. `-xml` is ignored. Each line is
   `<status text>` or `<status text>: <detail text>`, with the texts from the `validationmessages` bundle
   (`es_ES` shown):

   | Validity | Status text |
   |---|---|
   | `OK`, `GENERATED` | `Firma válida` |
   | `UNKNOWN` | `Validación incompleta` |
   | `PENDING_CONFIRM_BY_USER` | `Validez a confirmar por el usuario` |
   | `KO` | `Firma no válida` |

   | Error | Detail text (`SignValidationMessage.N`) |
   |---|---|
   | `NO_DATA` | `no se puede comprobar la validez por no tener los datos firmados` (4) |
   | `CORRUPTED_SIGN` | `la informaci&oacute;n contenida en la firma no es consistente (certificados corruptos, etc.)` (5) |
   | `NO_MATCH_DATA` | `la firma no se corresponde con los datos firmados` (6) |
   | `NO_SIGN` | `no se encuentra la firma dentro del documento` (7) |
   | `CERTIFICATE_PROBLEM` | `no se puede extraer un certificado o este no es v&aacute;lido` (8) |
   | `CERTIFICATE_EXPIRED` | `existe un certificado de firma caducado` (9) |
   | `CERTIFICATE_NOT_VALID_YET` | `existe un certificado de firma que aun no es v&aacute;lido` (10) |
   | `CANT_VALIDATE_CERT` | `no se ha podido validar el certificado correctamente` (11) |
   | `ALGORITHM_NOT_SUPPORTED` | `la firma contiene un algoritmo no reconocido o no soportado` (12) |
   | `CA_NOT_SUPPORTED` | `no se soporta la CA de expedici&oacute;n` (13) |
   | `CRL_PROBLEM` | `existe algun problema con las CRLs incrustadas en la firma` (14) |
   | `PDF_UNKOWN_VALIDITY` | `no se puede comprobar la validez de la firma PDF` (15) |
   | `OOXML_UNKOWN_VALIDITY` | `no se puede comprobar la validez de la firma OOXML` (16) |
   | `ODF_UNKOWN_VALIDITY` | `no se puede comprobar la validez de la firma ODF` (17) |
   | `UNKOWN_ERROR` | `no se puede comprobar la validez de la firma` (18) |
   | `UNKOWN_SIGNATURE_FORMAT` | `los datos proporcionados no se corresponden con ning&uacute;n formato de firma reconocido` (19) |
   | `MODIFIED_DOCUMENT` | `el documento PDF es sospechoso de haberse modificado tras la firma` (20) |
   | `OVERLAPPING_SIGNATURE` | `las firmas del documento se solapan pudiendo ocultar informaci&oacute;n` (21) |
   | `MODIFIED_FORM` | `un formulario del documento fue modificado tras la firma` (22) |
   | `SUSPECTED_SIGNATURE` | `el documento es sospechoso y el usuario debe revisar la firma` (23) |
   | `SIGN_PROFILE_NOT_CHECKED` | `la firma contiene atributos longevos que Autofirma no puede validar. Para una validaci&oacute;n completa recurra a VALIDe.` (24) |
   | `CANT_VALIDATE_EXTERNALLY_DETACHED` | `no se permite la validaci&oacute;n de firmas con referencias externas` (25) |
   | `BAD_BUILD_SIGN` | `la firma no est&aacute; correctamente formada` (26) |
   | `CERTIFIED_SIGN_REVISION` | `El documento certificado no permit&iacute;a nuevas firmas` (27) |

   **Quirk:** some texts contain literal HTML entities (`&oacute;`), because they were written for HTML
   labels, and the console prints them as-is. The Rust version should store plain UTF-8 and render the
   entities only in HTML contexts.
   Example output: `Firma no válida: la firma no se corresponde con los datos firmados`.

#### 5.9.4 `verify -gui`

```
<launcher> verify -gui -i <file>
```
This opens the standalone signature viewer (`new VisorFirma(true, null).initialize(false, file)`, §2) on the
file. If `-i` is missing, the error is shown in a dialog and printed, with status -1. No exit is forced.
Windows registers it as the "Verificar con Autofirma" verb for `.csig` and `.xsig` (§5.13).

#### 5.9.5 `listaliases`

```
<launcher> listaliases [-store <s>] [-password <p>] [-xml]
```
1. Open the keystore (§5.5) and get **all** aliases, unfiltered. Certificates without a private key are
   included if the store lists them.
2. Plain output: each alias followed by `\n` (an empty store prints an empty line). Status 0.
3. XML output: `<afirma><result>ok</result><response><alias>A1</alias><alias>A2</alias></response></afirma>`.
   Note `ok` here, where sign responses use `true`/`false`. Aliases are **not XML-escaped**.
4. A keystore error (`IOException` or `KeystoreAlternativeException`) prints the exception message, or .49
   for an unavailable store, with status -1.

#### 5.9.6 `batchsign` (server-assisted XML batch)

```
<launcher> batchsign -i <batch.xml> (-o <result.xml> | -xml) (-alias <a> | -filter <f>)
                     -preurl <presign-URL> -posturl <postsign-URL> [-store <s>] [-password <p>] [-config <props>]
```
This is the **legacy XML three-phase batch** client (`BatchSigner.signXML` in `afirma-crypto-batch-client`).
It does **not** use the local batch engine (`LocalBatchSigner`, `JSONBatchManager`), which is only reached
through the `afirma://batch` protocol and is covered in the protocol spec.

Validation:
- `-i` is required (.5);
- `-alias` or `-filter` is required (.17); `-certgui` is ignored;
- `-o` or `-xml` is required (.19);
- both URLs are required (.60 `No se ha indicado la URL de postfirma o la URL de prefirma`).

Steps:
1. Open the keystore and resolve the alias, through the filter if one was given. The entry must exist (.61).
   No entry password callback is set.
2. Read the input. If the whole file passes `Base64.isBase64` (only Base64 alphabet characters, `=` only in
   the last 2 positions, length without CR/LF a multiple of 4), Base64-decode it. Otherwise use it as is.
3. Parse the XML securely. The root element must be `signbatch` (case-insensitive) and must have an
   `algorithm` attribute (e.g. `SHA256withRSA`). That attribute is the PKCS#1 algorithm used for the whole
   batch.
4. Pre-sign: HTTP POST to `<preurl>` with the form body `xml=<Base64URL(batchBytes)>&certs=<chain>`, where
   `<chain>` is the Base64URL (URL-safe alphabet) of each certificate DER, joined by `;`. The response is a
   `TriphaseData` XML (format in the protocol/triphase spec).
5. Compute PKCS#1 signatures locally for every pre-signature in the TriphaseData, using `AOPkcs1Signer` with
   the batch algorithm and no extra params.
6. Post-sign: HTTP POST to `<posturl>` with
   `xml=<Base64URL(batch)>&certs=<chain>&tridata=<Base64URL(UTF-8 of the signed TriphaseData XML)>`. The
   response body, decoded as UTF-8, is the **batch result XML** (format defined by the server).
7. Write the result to `-o` using platform-default bytes.
8. HTTP and server errors map to `AOException`s with batch error codes: 400 is invalid parameters, other 4xx
   is a communication error, 5xx is a service error, plus timeout and connection errors (batch-client spec).
   The `-config` properties are passed to the SSL error processor, which can, for instance, ask to trust a
   server certificate through the GUI.

Batch XML input (legacy schema, from `batch-with-countersign.xml`):
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<signbatch stoponerror="false" algorithm="SHA256withRSA">
 <singlesign Id="7725374e-728d-4a33-9db9-3a4efea4cead">
  <datasource>BASE64 data or URL</datasource>
  <format>XAdES</format>                     <!-- CAdES, XAdES, PAdES, FacturaE, ... -->
  <suboperation>countersign</suboperation>   <!-- sign | cosign | countersign -->
  <extraparams>BASE64(properties text)</extraparams>   <!-- e.g. Base64("target=tree") -->
  <signsaver>
   <class>es.gob.afirma.signers.batch.SignSaverFile</class>
   <config>BASE64(properties, e.g. "FileName=C:/out/CONTRAFIRMA1.xml")</config>
  </signsaver>
 </singlesign>
 ...
</signbatch>
```
The client only reads `algorithm`. Everything else is interpreted by the server.

**Gotchas:**
- **The response is discarded.** `processCommand` ignores `batchByCommandLine`'s return value, so on success
  **nothing** is printed and there is no `System.exit(0)`. Errors that `batchByCommandLine` catches itself
  (`IOException`, `KeyStoreException`, `NoSuchAlgorithmException`, `UnrecoverableEntryException`,
  `CertificateEncodingException`, `AOException`) are returned as strings and therefore **also dropped**.
  These cover keystore-open failures, including `KeystoreAlternativeException` (a subclass of
  `AOException`), file read errors and all network and server failures. The process then exits with status
  0. Only these errors are printed, with status -1: parameter errors, an unknown `-store` type, filter
  no-match or multi-match (.52/.53), alias not found (.61) and unexpected runtime exceptions.
- `-xml` without `-o` passes validation and then fails with `NullPointerException` when the output file is
  opened. It is printed as `Error no reconocido: null`, XML-wrapped, with status -1.
- The bundled server module in this repository (`afirma-server-triphase-signer`) only offers **JSON**
  batch endpoints (`json` parameter). The XML `xml=` protocol only works against older or third-party
  servers.
- **Rust recommendation:** implement `batchsign` faithfully (XML), optionally add a JSON variant, and
  print the result or error with proper exit codes.

#### 5.9.7 Plugin commands: `createdigest` and `checkdigest` (hash plugin, see §7)

These are dispatched only when the hash plugin is installed and holds the `COMMANDS` permission. The
plugin receives the arguments without the command token. It has its own parser (`HashParameters`) and its
own messages (`CommandLine.*` keys in the plugin's `messages.properties`).

Parser rules: options are case-sensitive. `-i` and `-o` check existence and readability or parent
writability at parse time. A duplicate gives `Parametro duplicado: <opt>`. The first token may be the
positional FILE or DIRECTORY. Errors are `IllegalArgumentException`s, which the launcher prints as
`Error no reconocido: <msg>` with status -1 (no syntax help).
**Quirk:** `-halgorithm` and `-hformat` do not check that a value follows, so a missing value gives
`ArrayIndexOutOfBounds`, reported as the generic error.

```
createdigest FICHERO|DIRECTORIO [-gui] [-o FICHERO] [-halgorithm ALGORITMO] [-hformat FORMATO] [-r]
checkdigest  [FICHERO|DIRECTORIO] [-gui] [-i FICHERO_HUELLAS] [-o FICHERO_INFORME] [-d]
```

| Option | Meaning |
|---|---|
| positional `FICHERO` or `DIRECTORIO` | The file or directory to hash or check. Mandatory for `createdigest` (`No se ha indicado ningun fichero o directorio`); optional for `checkdigest` (with `-gui` the user is asked). Existence and readability are checked (`El fichero o directorio indicado no existe: %0`, `No hay permisos de lectura sobre el fichero o directorio indicado: %0`). |
| `-gui` | Run the operation through the plugin dialogs (§7). The process ends with `Runtime.halt(0)` afterwards. |
| `-o FILE` | createdigest: output hash file; without it the result goes to stdout. checkdigest on a directory: path of the XML validation report. |
| `-i FILE` | checkdigest: the hash file to verify against. Required in console mode (`No se ha especificado un fichero de huellas`). |
| `-halgorithm ALG` | Digest algorithm (Java name, e.g. `SHA-256`, `SHA-512`). Default `SHA-256`. |
| `-hformat F` | File input: `hex` (default), `b64`, or `bin` (requires `-o`, otherwise `La generacion de la huella en binario requiere que se indique fichero de salida`). Directory input: `xml` (default) or `txt`. A wrong family gives `No se ha indicado un formato de salida de huella digital de {directorios|fichero} valido: %0`. |
| `-r` | Directory: recurse into subdirectories. |
| `-d` | Hidden option of checkdigest: with `-gui` and no positional argument, ask for a **directory** instead of a file. |
| `-xml` | Accepted, unused. |

Console outputs:
- `createdigest <file>`: `hex` gives uppercase hexadecimal followed by the letter `h` (e.g. `9F86…08h`);
  `b64` gives standard Base64; `bin` writes raw bytes to `-o`.
- `createdigest <dir>`: an XML or TXT document of all file hashes (formats in §7).
- With `-o`, the console prints `La operacion ha terminado correctamente ` instead.
- `checkdigest`: prints `Comprobacion de huella digital finalizada sin errores` when every hash matches,
  otherwise `Las huellas indicadas no se corresponden con las del archivo de entrada`. Status 0 in both
  cases.
- Help: `createdigest -help`, `checkdigest -help`, or `checkdigest` with no arguments, prints a "Sintaxis:"
  block that hard-codes `Autofirma` as the program name.

### 5.10 Response formats

Plain mode prints the success message or result text.

XML mode (`-xml`) wraps sign, cosign, countersign, batchsign and error responses (`buildXmlResponse`):
```xml
<afirma><result>true|false</result><response><msg>MESSAGE</msg><sign>BASE64</sign></response></afirma>
```
- The whole document is on a single line, with no XML declaration.
- `<response>` is omitted when there is neither a message nor a signature. `<msg>` is omitted when the
  message is null, and `<sign>` when there are no bytes.
- Base64 is standard, without line breaks.
- Message and signature are **not XML-escaped** (quirk; the Rust version should escape).
- Errors in XML mode: `<afirma><result>false</result><response><msg>…</msg></response></afirma>`.
- **Quirk:** parameter-syntax errors (`CommandLineParameterException`) are **never** XML-wrapped. They always
  print the text message followed by the command help.

`listaliases` XML: see §5.9.5. `verify`: always plain.

### 5.11 Error handling and message mapping (`processCommandLine`)

| Exception caught | Optional GUI | Printed text | Status |
|---|---|---|---|
| `CommandLineParameterException` (missing or invalid option values, unknown format or store, unsupported key type, missing `-i`/`-o`/alias, …) | Error dialog when `usingGui` (§5.12) | `buildSyntaxError(command, msg)`, i.e. the message followed by the command help (§5.3.2). Never XML. | -1 |
| `CommandLineException` | Error dialog when `usingGui` | Cause is a `KeystoreAlternativeException`: `El almacen de claves seleccionado no esta disponible: <cause msg>` (.49). Any other cause: `cause.getMessage()`. No cause: `e.getMessage()`. XML-wrapped when `-xml` is present. **Quirk:** a null cause message prints **nothing**. | -1 |
| `PluginControlledException` or `UnsupportedOperationException` (unknown command, plugin-controlled errors) | | `e.getMessage()`, XML-wrapped when `-xml` is present. An unknown command prints `Comando no reconocido: X` followed by the general help. | -1 |
| Any other `Exception` (including `IllegalArgumentException` from plugins, `NullPointerException`, `AOCancelledOperationException`) | | `Error no reconocido: <e.getMessage()>` (.50), XML-wrapped when `-xml` is present | -1 |
| Success | | Response text, when non-null | 0 |

The full message catalogue (key, Spanish, English) is the `CommandLineLauncher.*` table in Appendix 5.A.

### 5.12 GUI pop-ups that can appear in CLI mode

The CLI is not guaranteed to be non-interactive, and a headless Rust CLI must decide how to handle each of
these cases. Recommended: fail with a clear error when `--non-interactive` or `headless=true` is set.
1. **Parameter-error dialog.** When the failing exception has `usingGui=true` (`-gui` was seen earlier, or
   `sign -gui`/`verify -gui` without `-i`), a modal error dialog with title `Error en los parámetros de
   entrada` (.127) is shown before printing.
2. **Certificate selection dialog** with `-certgui` (§5.6).
3. **Keystore password or PIN prompts** when `-password` is missing (PKCS#12, NSS master password), DNIe and
   PKCS#11 PIN dialogs, and Windows CAPI/smart-card middleware prompts.
4. **Signer dialogs** when `headless` is not `true` in `-config`. Examples: confirming the signature of a
   certified PDF, a PDF with a suspected shadow attack or modified form, a password-protected PDF, or a
   different-profile confirmation. These come from the signer layer through `AOUIFactory`.
5. **SSL trust prompt** for unknown server certificates in `batchsign`, through `SSLErrorProcessor`.
6. **Full GUI** for `sign -gui`, `verify -gui` and the hash plugin `-gui` modes.

### 5.13 OS integrations that invoke the CLI

Exact registry keys and installer steps are in §9.
- Windows, all files: `HKCR\*\shell\afirma.sign` has default value `Firmar con Autofirma` (localised:
  `Sign with Autofirma`, `Signar amb Autofirma`, …), `Icon` = path of `Autofirma.exe`, and
  `\command` = `<INSTDIR>\Autofirma\Autofirma.exe sign -gui -i "%1"`.
  **Gotcha:** the exe path is not quoted. The Rust installer must quote it.
- Windows, `.csig` and `.xsig`: `HKCR\.csig\shell\Verify` and `HKCR\.xsig\shell\Verify` have default value
  `Verificar con Autofirma`, and `\command` = `<…>\Autofirma.exe verify -gui -i "%1"`. The same keys set
  `DefaultIcon` = `ic_firmar.ico`.
- Windows, hash plugin (§7): `HKCR\*\shell\afirma.hashFile\command` = `<exe> createdigest "%1" -gui`;
  `HKCR\Directory\shell\afirma.hashDirectory\command` = `<exe> createdigest "%1" -gui`;
  `.hash`, `.hashb64` and `.hexhash` get `checkdigest -i "%1" -gui`; `.hashfiles` gets
  `checkdigest -i "%1" -d -gui`.
- Linux `.desktop`: `Exec=/usr/bin/autofirma %u` (deb) or `Exec=java … -jar …/autofirma.jar %u` (rpm). Only
  the `x-scheme-handler/afirma` MIME type is registered, so Linux has no file "Open with → sign" integration.
  A path passed as `%u` would hit the unknown-command error (§5.1.1).

### 5.14 Examples

```sh
# List aliases in a PKCS#12 file (XML answer)
autofirma listaliases -store pkcs12:/home/u/cert.p12 -password 1234 -xml
# -> <afirma><result>ok</result><response><alias>anf usuario activo</alias></response></afirma>

# PAdES signature, alias selection, visible signature on page 1
autofirma sign -i in.pdf -o out.pdf -store pkcs12:/home/u/cert.p12 -password 12341234 \
  -alias "anf usuario activo" -format pades \
  -config 'signaturePositionOnPageLowerLeftX=100\nsignaturePositionOnPageLowerLeftY=100\nsignaturePositionOnPageUpperRightX=200\nsignaturePositionOnPageUpperRightY=200\nsignaturePage=1'
# -> La operacion ha terminado correctamente

# Visible signature on pages 2-4 and 6
...  -config 'signaturePositionOnPageLowerLeftX=100\n...\nsignaturePages=2-4,6'

# CAdES (auto) on Windows store, certificate chosen by filter, signature returned in XML
AutofirmaCommandLine sign -i data.bin -xml -store windows -filter "subject.contains:12345678Z;nonexpired:"
# -> <afirma><result>true</result><response><msg>La operacion ha terminado correctamente </msg><sign>MIAGCSqGSIb3...</sign></response></afirma>

# Countersign the whole tree of a XAdES signature with a GUI certificate chooser
autofirma countersign -i firma.xsig -o firma_cs.xsig -format xades -certgui -config "target=tree"

# Verify
autofirma verify -i firma.csig
# -> Firma válida

# Open the GUI preloaded with a document (Windows Explorer verb)
Autofirma.exe sign -gui -i "C:\docs\contrato.pdf"

# Server-assisted XML batch (from BatchFromCommandLine)
autofirma batchsign -i batch-with-countersign.xml -o result.xml -alias "FISICO ACTIVO PRUEBA - 881146077" \
  -preurl http://localhost:8080/afirma-server-triphase-signer/BatchPresigner \
  -posturl http://localhost:8080/afirma-server-triphase-signer/BatchPostsigner

# Hash plugin
autofirma createdigest informe.pdf -halgorithm SHA-512 -hformat b64
autofirma createdigest ./carpeta -r -hformat txt -o huellas.txt
autofirma checkdigest informe.pdf -i informe.pdf.hexhash
```

### 5.15 Summary of quirks and recommendations for the Rust implementation

1. CLI mode is triggered by **any** first argument that is not `afirma://…`. Keep this, and consider also
   accepting a bare file path to mean "open in GUI".
2. Everything goes to **stdout**, errors included, and the error status is **-1/255**. Keep both for
   compatibility, and optionally add `--stderr` behaviour behind a flag.
3. The non-GUI CLI default digest is **SHA-512**, while the GUI preference default is SHA256.
4. `-format auto` in the CLI chooses only PAdES, XAdES or CAdES by content sniffing (no FacturaE, OOXML or
   ODF). The GUI path has an inverted condition (`-format` ignored when not `auto`).
5. `sign -gui` drops `-config` **and** the preference extra params (likely a bug). Decide explicitly.
6. `batchsign` prints nothing and exits 0 even on failure. Fix it, but keep the success semantics (result
   file written).
7. XML responses are not escaped. Escape them in Rust; that remains backward compatible for normal values.
8. `-operation`, `-hformat`, `-halgorithm` and `-r` are accepted and ignored by built-in commands. Keep
   accepting them for script compatibility.
9. `-config` uses a literal `\n` separator, with the parser rules of §5.7.
10. `AOConfigurableContext.setSecureMode(false)` lets extra params refer to local files. Keep it for the CLI
    only, never for `afirma://` invocations.
11. There is no `-version`. The Rust version may add `--version` and `-version` (they currently produce
    "unknown command").

#### Appendix 5.A — `CommandLineLauncher.*` message catalogue (es_ES / en_US)

The English texts are copied verbatim from `commandlinemessages_en_US.properties`. They are machine
translations of poor quality ("warehouse" for *almacén*, "Sets the back of the store" for the store
password, "file counter" for *contrafirma*). A new English catalogue is recommended.

| Key | es_ES | en_US |
|---|---|---|
| `CommandLineLauncher.0` | El fichero de entrada no existe: %0 | The input file does not exist: %0 |
| `CommandLineLauncher.1` | No hay permisos de lectura para el fichero de entrada: %0 | No reading permissions for the input file: %0 |
| `CommandLineLauncher.3` | No hay permisos de escritura en el directorio especificado para el fichero de salida: %0 | No writing permissions in the specified directory for the output file: %0 |
| `CommandLineLauncher.4` | Formato de firma no soportado: %0 | Unsupported signature format: %0 |
| `CommandLineLauncher.5` | No se ha especificado un fichero de entrada | No input file specified |
| `CommandLineLauncher.7` | Sintaxis | Syntax |
| `CommandLineLauncher.8` | firma de fichero | file signing |
| `CommandLineLauncher.9` | cofirma de fichero | file co-signing |
| `CommandLineLauncher.10` | contrafirma de fichero | file counter |
| `CommandLineLauncher.11` | lista los alias disponibles en el almacen | list the aliases available in the warehouse |
| `CommandLineLauncher.12` | Establece la contrasena del almacen | Sets the back of the store |
| `CommandLineLauncher.13` | Ruta del fichero de entrada | Input file path |
| `CommandLineLauncher.14` | Ruta del fichero de salida | Output file path |
| `CommandLineLauncher.15` | Comando no reconocido: %0 | Unrecognized command: %0 |
| `CommandLineLauncher.16` | Alias del certificado de firma | Alias of signature certificate |
| `CommandLineLauncher.17` | Se tiene que especificar un alias o un filtro para la seleccion del certificado de firma | An alias or filter must be specified for selecting the signature certificate |
| `CommandLineLauncher.18` | Formatea la respuesta como XML | Format the answer as XML |
| `CommandLineLauncher.19` | No se ha indicado un fichero de salida | No output file indicated |
| `CommandLineLauncher.20` | Algoritmo de firma | Signing algorithm |
| `CommandLineLauncher.21` | No se ha podido escribir en el fichero de salida: %0 | Unable to write in the output file: %0 |
| `CommandLineLauncher.22` | La operacion ha terminado correctamente  | The operation is completed correctly |
| `CommandLineLauncher.23` | Realiza la operacion con entorno grafico. | Perform the operation with graphic environment. Priority over %0 |
| `CommandLineLauncher.25` | No se reconoce el parametro %0 | Parameter %0 is not recognized |
| `CommandLineLauncher.26` | Parametro duplicado: %0 | Duplicate bracket: %0 |
| `CommandLineLauncher.27` | Properties en texto plano con la configuracion de la operacion | Properties in plain text with operation configuration |
| `CommandLineLauncher.28` | Las opciones '-alias' y '-filter' son excluyentes | Options '-alias' and '-filter' are exclusionary |
| `CommandLineLauncher.29` | abre un panel con la informacion de validacion de una firma o certificado | opens a panel with the validation information of a signature or certificate |
| `CommandLineLauncher.30` | Utilice "%0 cmd -help" para ver la sintaxis del comando "cmd" | Use "%0 cmd -help" to view the "cmd" command syntax |
| `CommandLineLauncher.31` | Establece el almacen de claves. Por defecto, el del sistema | Sets the store of keys. By default, the system |
| `CommandLineLauncher.32` | Establece el formato de firma | Sets the signature format |
| `CommandLineLauncher.33` | Comandos | Commands |
| `CommandLineLauncher.34` | Herramienta de firma de documentos. | Document signing tool. |
| `CommandLineLauncher.36` | Almacen de claves del sistema | Store system keys |
| `CommandLineLauncher.37` | Almacen de claves de Windows | Store Windows Keys |
| `CommandLineLauncher.38` | Almacen de claves de macOS | Store macOS keys |
| `CommandLineLauncher.39` | Almacen de claves de Mozilla Firefox | Store Mozilla Firefox Keys |
| `CommandLineLauncher.40` | DNI electronico | Electronic ID |
| `CommandLineLauncher.41` | Almacen PKCS#12. "p12file" es la ruta del almacen | Store PKCS#12. "p12file" is the stock route |
| `CommandLineLauncher.42` | Seleccion de formato en base al fichero de entrada | Format selection based on input file |
| `CommandLineLauncher.43` | Formato CAdES | Format CAdES |
| `CommandLineLauncher.44` | Formato PAdES | Format PAdES |
| `CommandLineLauncher.45` | Formato XAdES | Format XAdES |
| `CommandLineLauncher.46` | Firma de factura electronica | Electronic invoice signing |
| `CommandLineLauncher.47` | Almacen PKCS#11. "p11file" es la ruta del controlador | Store PKCS#11. "p11file" is the driver path |
| `CommandLineLauncher.48` | Tipo de almacen desconocido: %0 | Unknown stock type: %0 |
| `CommandLineLauncher.49` | El almacen de claves seleccionado no esta disponible: %0 | The selected key store is not available: %0 |
| `CommandLineLauncher.50` | Error no reconocido: %0 | Unrecognized error: %0 |
| `CommandLineLauncher.52` | No se han encontrado certificados que se ajusten al filtro establecido | No certificates have been found to fit the established filter |
| `CommandLineLauncher.53` | Se ha encontrado mas de un certificado a partir del fitro establecido | More than one certificate has been found from the established fitro |
| `CommandLineLauncher.54` | Comando no soportado: %0 | Unsupported command: %0 |
| `CommandLineLauncher.59` | La direccion indicada ('%0') debe ser una URL valida: %1 | The indicated address ('%0') must be a valid URL: %1 |
| `CommandLineLauncher.60` | No se ha indicado la URL de postfirma o la URL de prefirma | Post-signature URL or pre-signature URL not indicated |
| `CommandLineLauncher.61` | No se ha encontrado ninguna entrada en el almacen con el alias '%0', puede listar las entradas actuales con el comando "listaliases" | No entry was found in the store with the alias '%0', can list the current entries with the command "listaliases" |
| `CommandLineLauncher.62` | Ruta del fichero de configuracion de la operacion | Operating configuration file path |
| `CommandLineLauncher.63` | Ruta del fichero con el XML resultado de la operacion | File path with XML operating result |
| `CommandLineLauncher.64` | URL del servicio externo de prefirma | External Presignature Service URL |
| `CommandLineLauncher.65` | URL del servicio externo de postfirma | External post-signature service URL |
| `CommandLineLauncher.66` | Filtro para seleccionar el certificado de firma | Filter to select the signing certificate |
| `CommandLineLauncher.69` | firma/multifirma de lotes de ficheros | signature/multi-signature file lots |
| `CommandLineLauncher.72` | Formato OOXML | OOXML format |
| `CommandLineLauncher.73` | Formato ODF | ODF format |
| `CommandLineLauncher.74` | No se ha indicado fichero de entrada | No input file indicated |
| `CommandLineLauncher.75` | No se ha indicado fichero de salida | No output file indicated |
| `CommandLineLauncher.76` | Usa un dialogo grafico para la seleccion del certificado de firma | Use a graphic dialogue to select the signing certificate |
| `CommandLineLauncher.89` | Formato de salida de huella digital no soportado: %0 | Unsupported fingerprint output format: %0 |
| `CommandLineLauncher.115` | Opciones | Options |
| `CommandLineLauncher.120` | No se ha indicado ningun fichero o directorio | No file or directory indicated |
| `CommandLineLauncher.121` | El fichero o directorio indicado no existe: %0 | The listed file or directory does not exist: %0 |
| `CommandLineLauncher.122` | No hay permisos de lectura sobre el fichero o directorio indicado: %0 | No reading permissions on the given file or directory: %0 |
| `CommandLineLauncher.125` | No se pudieron cargar los comandos de los plugins instalados. | The commands of the installed plugins could not be loaded. |
| `CommandLineLauncher.126` | Comandos agregados a traves de plugins | Commands added via plugins |
| `CommandLineLauncher.127` | Error en los parÃ¡metros de entrada | Error in input parameters |
| `CommandLineLauncher.128` | No se ha indicado URL de prefirma | No pre-signature URL indicated |
| `CommandLineLauncher.129` | No se ha indicado URL de postfirma | No postsignature URL indicated |
| `CommandLineLauncher.130` | No se ha indicado el nombre del almacÃ©n de claves | No key store name indicated |
| `CommandLineLauncher.131` | No se ha indicado la operaciÃ³n de firma masiva | Mass signing operation not indicated |
| `CommandLineLauncher.132` | No se ha indicado el algoritmo de firma | Signature algorithm not indicated |
| `CommandLineLauncher.133` | No se ha indicado el algoritmo de huella digital | No fingerprint algorithm indicated |
| `CommandLineLauncher.134` | No se ha indicado la configuraciÃ³n del formato de firma | Signature format settings not indicated |
| `CommandLineLauncher.135` | No se ha indicado la contraseÃ±a del almacÃ©n | Store password not indicated |
| `CommandLineLauncher.136` | No se ha indicado el alias del certificado | Certificate alias not indicated |
| `CommandLineLauncher.137` | No se ha indicado el filtro de certificados | Certificate filter not indicated |
| `CommandLineLauncher.138` | No se ha indicado el formato de firma | Signature format not indicated |
| `CommandLineLauncher.139` | No se ha indicado el formato de huella digital | Fingerprint format not indicated |
| `CommandLineLauncher.140` | opciones | options |
| `CommandLineLauncher.141` | El tipo de clave del certificado no esta soportado: %0 | The type of certificate key is not supported: %0 |
| `CommandLineLauncher.142` | Firma con algoritmo de huella SHA-1 (No recomendado) | Signature with SHA-1 fingerprint algorithm (Not recommended) |
| `CommandLineLauncher.143` | Firma con algoritmo de huella SHA-256 | Signing with SHA-256 fingerprint algorithm |
| `CommandLineLauncher.144` | Firma con algoritmo de huella SHA-384 | Signature with fingerprint algorithm SHA-384 |
| `CommandLineLauncher.145` | Firma con algoritmo de huella SHA-512 (Por defecto) | Signature with SHA-512 fingerprint algorithm (Default) |
| `CommandLineLauncher.146` | Tiene prioridad sobre %0 | (missing) |
| `CommandLineLauncher.147` | No se ha podido obtener la referencia a la clave privada | (missing) |
| `CommandLineLauncher.148` | No se hay ninguna entrada en el almacen con el alias indicado: %0 | (missing) |
| `CommandLineLauncher.149` | Error en la operacion de firma | (missing) |


## 6. Massive (directory/multi-file) signing

Two code paths exist, and a reimplementation must mirror the right one:

| Path | Where | Used by AutoFirma desktop? |
|---|---|---|
| **A. Desktop multi-file signing.** The user selects several files, or drops folders, on the main screen. | `afirma-simple`: `SignPanel`, `SignPanelSignTask`, `SignPanelMultiFilePanel`, `SignResultListPanel`, `MassiveResultProcessPanel` | **Yes.** This is the real "firma masiva" of AutoFirma. |
| **B. `afirma-core-massive` library.** Directory signing with `result.log`. | `DirectorySignatureHelper`, `MassiveSignatureHelper`, `MassiveSignConfiguration`, `MassiveType`, `LogHandler`, `DefaultLogHandler`, `MassiveErrorCode`, `MassiveSignMessages` | **No.** `afirma-simple/pom.xml` declares the dependency, but no class in `afirma-simple` references `es.gob.afirma.massive`. Its consumers are legacy components (`afirma-ui-applet`, `afirma-standalone`, `afirma-ui-simple-webstart`). |

The CLI has **no** massive command (§5.4.2). `-operation` and `-r` are legacy leftovers that are parsed and
ignored, and the messages `CommandLineLauncher.55`–`58` ("Operacion masiva de firma/cofirma/contrafirma")
are unused.

Section 6.1 specifies path A, the behaviour users see. Section 6.2 specifies library B for completeness,
since it defines AutoFirma's historical directory-signing semantics: output naming, `result.log`,
"respetar formato original".

### 6.1 Desktop multi-file signing (actual AutoFirma behaviour)

#### 6.1.1 Selecting the input set

- **Main screen button** `Seleccionar ficheros a firmar` (`SignPanel.32`, mnemonic `S`) opens a file chooser
  with title `Seleccione el fichero a firmar` (`SignPanel.35`), in *files-only, multi-select* mode.
- **Drag & drop** of any number of files and/or folders onto the main screen (`DropDataFileListener`, §2).
- **Menu** entry `Abrir archivo a firmar` (`MainMenu.2`, §2).
- `sign -gui -i <file>` preloads exactly one file (§5.9.2).

`SignPanel.filterFiles(files)` expands the selection:
1. A work list starts with the selected items. While iterating, every item that exists and is readable is
   handled as follows: a regular file is added to the result; a directory has all its children appended to
   the work list. The traversal is therefore breadth-first, **recursive to any depth**, unfiltered (hidden
   files, any extension, unsorted `listFiles()` order). Symlinks are followed by Java semantics.
2. Missing or unreadable items are silently skipped.
3. If nothing remains: an error dialog `No se ha podido cargar el fichero seleccionado.` (`SignPanel.123`,
   title `SimpleAfirma.7`) with internal code `LOADING_LOCAL_FILE_ERROR`.

Each file is read completely into memory and analysed (`SignPanel.prepareSignConfig`), which determines its
file type and default signer from the per-type preferences (`defaultSignatureFormatPdf`, `…Facturae`,
`…Ooxml`, `…Odf`, `…Xml`, `…Bin`; see §2 and §4 for the detection order). Existing signatures
(CAdES/XAdES) become `SIGN_CADES`/`SIGN_XADES` with a cosign operation; a PDF that is already signed gets
`COSIGN`. Files that cannot be read (I/O error, `OutOfMemoryError`) are logged and **dropped from the list
without a message**.

- One resulting file → single-file mode (`SignPanelFilePanel`, §2).
- More than one → **multi-file mode** (`SignPanelMultiFilePanel`).

There is no upper limit on the number of files.

#### 6.1.2 Multi-file list (before signing)

`SignPanelMultiFilePanel` shows a `JList` with a header row of 3 columns: `Fichero` (`SignDataPanel.43`),
`Formato` (`.44`), `Tamaño` (`.45`). Each row contains:
- a 32×32 file-type icon (`FileType` icon);
- the path relative to the common base. The base is the shortest parent directory among all inputs; the
  label is `absolutePath.substring(len(base)+1)`.
  - If the existing signature is invalid, the label gets the suffix ` (Firma inválida)` (`SignPanel.147`)
    and is drawn in red.
  - If the signature needs user confirmation, the suffix is ` (<validity text>)`, also in red.
- the signature format name (e.g. "PAdES", "CAdES", "XAdES");
- the size: `0 KB` when 0; `1 KB` when below 1024 bytes; `N KB` below 1 024 000 bytes (N = bytes/1024,
  integer, locale grouping); otherwise `M MB` (integer bytes/1 048 576 formatted with `#.#`, so no decimals
  in practice).

The accessible description of the list is `Lista de archivos a firmar ` followed by, for each item,
`Fichero <name> Formato <fmt> Tamaño <n>KB`. Double-click or the context menu offers `Ver Fichero`
(`SignPanel.51`) and `Ver atributos de firma` (`SignPanel.148`), see §2. The sign button is enabled once the
default keystore has loaded.

#### 6.1.3 Pressing "Firmar" (`SignPanel.sign`)

1. When **exactly one** file is loaded, its existing signature is invalid (`KO`), and preference
   `allowInvalidSignatures` is `false` (default): error dialog
   `No se permite agregar nuevas firmas a documentos con firmas no válidas.` (`SimpleAfirma.9`), and the
   operation stops. In multi-file mode no such dialog appears; those files are skipped in step 4.
2. When preference `confirmToSign` is `true` (default), `ConfirmSignatureDialog` opens (§2) with the text
   `Se va a realizar la firma electrónica de %0 documentos.` (`ConfirmSignatureDialog.2`). Cancel aborts.
   Accepting with "Omitir esta confirmación en futuras operaciones de firma." ticked sets `confirmToSign`
   to `false` and persists it.
3. **Multisign operation per file type.** Every `SIGN_CADES` file gets the operation from preference
   `cadesMultisign`, and every `SIGN_XADES` file the one from `xadesMultisign`. Values: `cosign` → COSIGN,
   `countersignLeafs` → COUNTERSIGN_LEAFS, anything else (`countersignTree`) → COUNTERSIGN_TREE. Both
   default to `cosign`.
4. **PDF handling.** If any file uses the PAdES signer:
   - In multi-file mode, visible-signature options come from preferences: `visible := padesVisibleSignature`;
     no visible stamp. **Quirk/bug:** `allowCertifiedPdf` is also read from `padesVisibleSignature`, so the
     certification level `padesCertificationLevel` is applied only when visible signatures are enabled.
   - When a certification level other than `0` applies, `certificationLevel=<level>` is added to every
     config.
   - The configs are cloned and `VisiblePdfSignatureManager.getVisibleSignatureParams(...)` runs: §3 covers
     the visible-signature dialogs for one or many PDFs. Cancelling the dialog aborts. If the dialog fails,
     the signing continues **invisibly**.
5. `SignPanelSignTask` runs in the background while a modal wait dialog is shown: title
   `Proceso de firma electrónica` (`SignPanel.50`), text
   `Realizando la firma electrónica... Esta tarea puede tardar varios minutos.` (`SignPanel.48`).

#### 6.1.4 Signing loop (`SignPanelSignTask.doSignature`)

Order of interactions: **certificate first, then output directory**.

1. **Certificate.** The certificate selection dialog (§3) opens with the preference filters:
   - `useOnlySignatureCertificates` → key-usage filter for signing;
   - `skipAuthCertDnie` → skip the DNIe authentication certificate;
   - `useOnlyAliasCertificates` → pseudonym filter, pseudonym certificates only.
   When several of these are on, they are combined with AND. The dialog shows expired certificates
   according to `showExpiredCerts` (§4), and checks private keys and validity. Cancel ends silently.
   "No certificates" gives error `El almacén no contiene ningún certificado que se pueda usar para firmar.`
   (`SignPanel.29`). Other failures give `Se encontró un error durante la operación con el certificado
   seleccionado.` (`SignPanel.56`).
2. **Output directory** (multi-file only). A directory chooser opens with title
   `Seleccione el directorio de salida` (`SignPanelSignTask.3`), initial directory = the parent of the first
   file, single directory selection. Cancel ends silently, without signing and without a message.
3. **Input base path.** `inputBasePath` = the shortest `parent.getAbsolutePath()` among all input files
   (compared by string length).
4. For **each** config, in list order:
   1. **Skip** if the config has a validity whose first entry is `KO` and `allowInvalidSignatures=false`.
      The row will show as failed.
   2. Merge **all JVM system properties** into the extra params (`addExtraParams(System.getProperties())`).
      This is a legacy hook: `-Dkey=value` on the JVM command line becomes a signer option. Rust: optional,
      e.g. an env-var based override.
   3. Multi-file: set `headless=true`, so no signer dialogs appear. A file that would need user input fails
      with `RuntimeConfigNeededException` and is skipped. In single-file mode the confirm or password request
      is shown instead, and the task may be relaunched (§2).
   4. Read the file. On failure, skip it (single mode: error `SignPanel.123`).
   5. Plugin pre-processing: every plugin with permission `PRESIGN` gets `preSignProcess(data, formatName)`
      (§7).
   6. **Digest algorithm:** `config.digestAlgorithm`, set only by `sign -gui`, else preference
      `signatureHashAlgorithm` (default `SHA256`). It is combined with the key type into `SHA256withRSA` etc.
      (§5.8). An unsupported key type gives an error dialog and aborts the whole loop.
   7. **Operation** by crypto operation: `SIGN` → `sign`; `COSIGN` → `cosign`; `COUNTERSIGN_LEAFS` and
      `COUNTERSIGN_TREE` → `countersign` with target `LEAFS` or `TREE`.
      - PAdES `IncorrectPageException`: drop `signaturePage` and `signaturePages` and retry.
      - `InvalidSignaturePositionException`: also drop the 4 position keys and retry.
      In both cases the file name is recorded in `invalidPageNumberFilesList`.
   8. Per-file error policy in multi-file mode:
      - `AOFormatFileException`, `RuntimeConfigNeededException`, `SingleSignatureException`, any other
        `Exception`, `OutOfMemoryError` or `Error` → **skip and continue**, no dialog.
      - Cancellation (`AOCancelledOperationException`, smart-card cancel) → **abort the whole loop**, with no
        results screen.
      - Wrong PIN (`PinException`) → reload the keystore, re-select the **same** certificate (filter by
        encoded certificate, mandatory) and restart the **whole** loop from the first file. Restarting asks
        for the output directory **again**, and files already signed are re-signed (index-suffixed copies
        when `massiveOverride=false`).
      - `LockedKeyStoreException` → dialog `SignPanel.161`, abort.
      - `AuthenticationException` → dialog `SignPanel.162`, abort.
   9. Plugin post-processing: every plugin with permission `POSTSIGN` gets
      `postSignProcess(signature, formatName, certChain)` (§7).
   10. **Save** (multi-file):
       - `defaultName = signer.getSignedName(dataFile.getName(), "_signed")` (naming table below);
       - `relative = dataFile.parent.absolutePath.substring(len(inputBasePath)) + File.separator`;
       - `target = outDir / relative / defaultName`.
       - **Collision rule.** When preference `massiveOverride` is `false` (default), find the first
         `i = 1, 2, …` for which `<base>(i)<ext>` is not an existing regular file, where `<base>` is the name
         up to its **last** `.` and `<ext>` is from that `.` inclusive. With `massiveOverride=true`, the
         existing file is overwritten.
       - Missing parent directories are created (`mkdirs`). If that fails, an `IOException` is raised, the
         file is skipped and the row shows as failed.
       - On success, `config.signatureFile = written file`.
5. After the loop, every plugin's `reset()` is called.
6. **Results** (multi-file): `SimpleAfirma.showResultsInfo(configs, outDir, signingCert)` shows
   `SignResultListPanel` (6.1.5). The window title becomes `<app title> - <outDir absolute path>`, and on
   macOS the root pane property `Window.documentFile = outDir` is set.
7. If `invalidPageNumberFilesList` is non-empty, a warning dialog follows (title `SimpleAfirma.48`). Its
   text is `No se pudo aplicar la firma visible correctamente a los siguientes documentos, ya que la
   posición o páginas donde introducir la misma se encontraba fuera de rango:` (`SignResultPanel.34`), then
   one file name per line. The list is static and cleared afterwards.

Single-file mode differs only in saving: a "Save" dialog (`Guardar fichero firmado`, `SignPanel.81`)
proposes `signer.getSignedName(name, "_signed")` in the data file's directory, with a type filter that
depends on the signer:
- PDF: `Documentos Adobe PDF (*.pdf)`;
- XAdES/FacturaE: `Firmas XML (*.xml, *.xsig)`;
- OOXML: docx, pptx, xlsx or `*.ooxml`;
- ODF: odt, odp, ods or `*.odf`;
- otherwise: `Firmas binarias (*.csig, *.p7s)`.
After saving, the single-result screen opens (§2).

**Output naming** (`AOSigner.getSignedName(originalName, inText)` with `inText="_signed"`):

| Signer | Rule | Example |
|---|---|---|
| CAdES (`AOCAdESSigner`) | `name + inText + ".csig"` | `2.txt` → `2.txt_signed.csig`; `a.csig` (cosign) → `a.csig_signed.csig` |
| XAdES (`AOXAdESSigner`) and FacturaE (delegates to XAdES) | `name + inText + ".xsig"` | `2.xml` → `2.xml_signed.xsig`; `factura.xml` → `factura.xml_signed.xsig` |
| PAdES (`AOPDFSigner`) | Name ending in `.pdf` (case-insensitive): `stem + inText + ".pdf"`; otherwise `name + inText + ".pdf"`; null name: `signed.pdf` | `2.pdf` → `2_signed.pdf`; re-signing gives `2_signed_signed.pdf` |
| OOXML (`AOOOXMLSigner`) | Name ending in `.docx`, `.xlsx`, `.pptx` or `.ppsx`: `stem + inText + ext`; otherwise `name + inText + ".ooxml"` | `2.docx` → `2_signed.docx`, then `2_signed_signed.docx` |
| ODF (`AOODFSigner`) | Name ending in `.odt`, `.odp` or `.ods`: `stem + inText + ext`; a name no longer than 4 chars, or another extension: `name + inText + ".odf"` | `2.odt` → `2_signed.odt` |
| CAdES-ASiC-S / XAdES-ASiC-S | `name + inText + ".asics"` | `a.bin` → `a.bin_signed.asics` |

The test fixtures in `afirma-simple/src/test/resources/samples/` (`2_txt_signed.csig`, `2_xml_signed.xsig`)
were renamed by hand; the code produces `2.txt_signed.csig` and `2.xml_signed.xsig`.

**Worked example (multi-file).** Inputs dropped: the folder `/home/u/docs`, containing `a.pdf`, `b.txt` and
`sub/c.xml` (plain XML), plus `sub/d.csig` (a valid CAdES signature). Preferences are the defaults, the
output directory chosen is `/home/u/out`, and `/home/u/out/a_signed.pdf` already exists.
- `inputBasePath = /home/u/docs`.
- `a.pdf` → PAdES → `/home/u/out/a_signed(1).pdf`, because of the collision and `massiveOverride=false`.
- `b.txt` → CAdES (default for binary) → `/home/u/out/b.txt_signed.csig`.
- `sub/c.xml` → XAdES → `/home/u/out/sub/c.xml_signed.xsig`.
- `sub/d.csig` → CAdES with `cadesMultisign=cosign` → `/home/u/out/sub/d.csig_signed.csig`.

**Gotcha (relative paths).** `relative` is computed by string length, not by real path ancestry. For inputs
from unrelated trees (e.g. `/a/x/f1` and `/b/f2`), the base is `/b` and `f1` lands at `out/x/f1…`. Rust:
compute the deepest common ancestor and use proper relative paths.

#### 6.1.5 Result screen (`SignResultListPanel` + `MassiveResultProcessPanel`)

Preferred size 600×540. Top to bottom:
1. **Overall result banner** (`SignResultPanel`, §2):
   - all files have `signatureFile != null`: `Proceso finalizado correctamente` (`SignResultPanel.27`) with
     the text `Todas las firmas se han generado correctamente. Puede validar estas u otras firmas
     electrónicas en:` (`.28`), a link to `https://valide.redsara.es/` (`.33`), and icon tooltip
     `Todas las firmas del lote se han generado correctamente.` (`.29`);
   - any failure: `Proceso finalizado con errores` (`.30`), with `.31` (`Ocurrió un error al firmar uno o
     varios de los documentos seleccionados. Compruebe que estos documentos existen y pueden leerse. Firme
     los documentos individualmente si persiste el problema. Puede validar las firmas generadas
     correctamente en:`) and tooltip `.32`.
   Signatures are **not** validated after a multi-file run, unlike the single-file run.
2. Label `Directorio de firmas:` (`MassiveResultProcessPanel.3`) followed by a bordered box containing:
   - the absolute output directory path; right-clicking it offers `Copiar la ruta del directorio` (`.2`);
   - a button `Abrir directorio` (`.4`, mnemonic `b`, tooltip `.5` "Abre el directorio con las firmas
     generadas en su explorador de archivos"). It opens the folder in the OS file manager; on failure the
     error `.8` is shown.
3. Label `Certificado de firma utilizado:` (`SignDataPanel.21`) followed by a certificate box: type icon, holder
   (`CertificateInfo.1` "Titular del certificado:") as a link that opens the certificate details, and issuer
   (`CertificateInfo.2`) in bold.
4. The result list, with header columns `Fichero` (`.9`), `Tamaño` (`.10`) and `Estado` (`.11`). One row per
   input config, in processing order:
   - **success:** file-type icon; path of the written signature relative to the shortest output parent dir
     (`absolutePath.substring(minParentLen+1)`); size of the signature (same KB rules as 6.1.2 but never MB);
     icon `ok_icon_large.png`;
   - **failure:** icon; **absolute path of the input data file**; `0 KB`; icon `ko_icon_large.png`.
   Double-click or Enter on a success row opens the signature in the viewer (`VisorFirma`, non-standalone,
   §2). The accessible description is `Lista de documentos firmados ` followed by, per item,
   `Fichero <name> Estado Firma correcta Tamaño <n>KB` or `Fichero <name> Estado Firma incorrecta`.
5. The button `Firmar más ficheros` (`SignDetailPanel.0`, mnemonic `m`) returns to the main screen
   (`loadMainApp`).
6. The plugin button bar for integration point `MULTI_RESULT` (§7). Plugin actions of type
   `SignatureProcessAction` receive `OutputData[]` (signature file + format name) and the signing
   certificate.

The desktop path writes **no** log or report file. The on-screen list is the only report.

### 6.2 `afirma-core-massive` library (legacy directory signing)

#### 6.2.1 `MassiveType`

`SIGN`, `COSIGN`, `COUNTERSIGN_ALL` (target = TREE), `COUNTERSIGN_LEAFS` (target = LEAFS).

#### 6.2.2 `DirectorySignatureHelper`

**Constructor** `(algorithm, format, mode)`. All three are required (`IllegalArgumentException`).
`defaultSigner = AOSignerFactory.getSigner(format)`; an unknown format gives `AOUnsupportedSignFormatException`
(`"El formato de firma '<f>' seleccionado para la firma masiva no esta soportado"`).
Defaults used by callers (`AOSignConstants`): algorithm `SHA512withRSA`, mode `explicit`, format `CAdES`.

**Settings:**

| Setter | Default | Effect |
|---|---|---|
| `setFileFilter(java.io.FileFilter)` | none, i.e. all files | Applied to regular files during directory enumeration |
| `setOverwritePreviuosFileSigns(bool)` | `false` | Overwrite an existing output instead of adding an index |
| `setActiveLog(bool)` | `true` | Write log records |
| `setLogPath(path)` | null → `<outDir>/result.log` | Log file location. Blank strings count as null. |
| `setLogHandler(LogHandler)` | `DefaultLogHandler` | Custom sink |

**`massiveSign(type, startDir, recurse, outDir, createOutDir, originalFormat, keyEntry, config)`**
1. `config` must contain the keys `format` **and** `mode`; otherwise `IllegalArgumentException`
   (`"No se ha establecido el formato y modo de firma"`).
2. `startDir` is trimmed; when null or blank, `.` is used with a warning. It must exist and be a directory,
   else `AOException` with code `506001` "El directorio de entrada no existe". It must be readable, else
   `506002` "No se tiene acceso al directorio indicado". `inDir := absolute(startDir)`.
3. **Enumeration** (breadth-first, unsorted):
   - Each regular file is added. Without a filter it is added by `getPath()`, i.e. relative if `startDir` was
     relative; with a filter it is added by `getAbsolutePath()` when `filter.accept(file)`.
   - Directories are expanded only when `recurse`; unreadable ones are skipped with a warning.
4. Delegates to the file-list variant.

**`massiveSign(type, filenames[], outDir, createOutDir, originalFormat, keyEntry, config)`**
1. Same `format`/`mode` check. `signConfig := clone(config)` plus `headless=true`.
2. An empty file list returns `true` immediately (no log written).
3. `outputDir := outDir`, or `.` when null.
   - If it does not exist and `createOutDir`, run `mkdirs`.
   - If it does not exist or is not a directory: `IOException` "El directorio de salida no existe o existe
     un fichero con el mismo nombre".
   - If it is not writable: `IOException` "No se tienen permisos de escritura en el directorio de salida".
4. **Log file:** `FileOutputStream(logPath ?? outDir + separator + "result.log")`. It is opened (and
   **truncated**) even when the log is disabled.
   **Quirk:** this uses the raw `outDir` parameter, so a null `outDir` gives the path `null/result.log`.
5. `getFiles` re-validates each name. These are logged as SEVERE and skipped:
   - the file does not exist: `El fichero no existe` (DirectorySignatureHelper.0);
   - it is not a regular file: `El archivo es un directorio y no puede firmarse` (.1);
   - it is unreadable: `No se tienen permisos para leer el fichero` (.2).
6. Dispatch on `type` (null means SIGN; unknown types are only logged):
   - **SIGN** (`massiveSignOperation`), for each file:
     - `defaultSigner.isValidDataFile(bytes)` must hold (e.g. PAdES only accepts PDFs). Otherwise WARNING
       `El fichero no puede ser firmado con la configuración de firma actual` (.4), `allOK=false`. A read
       error gives SEVERE `No se pudo leer fichero` (.5); `OutOfMemoryError` gives
       `El fichero es demasiado grande` (.8).
     - `signConfig.uri = file.toURI()` (ASCII).
     - For the CAdES, XAdES and XMLDSig signers: XAdES or XMLDSig in **explicit** mode signs the **SHA-512
       digest** of the data with `mimeType=hash/sha-512`. Otherwise `mimeType` comes from `MimeHelper`. The
       OID derived from the MIME type, when known, is set as `contentTypeOid`.
     - `signer.sign(data, algorithm, key, chain, signConfig)`. Errors:
       - `UnsupportedOperationException` → SEVERE `No ha sido posible firmar el fichero - <msg>` (.7);
       - FacturaE already signed (`EFacturaAlreadySignedException`, matched by class name) → WARNING
         `La factura ya estaba firmada y no admite firmas adicionales` (.27);
       - other errors → SEVERE .7; OOM → .8.
     - Infix: `.signed`. For the PDF and OOXML signers (and ODF in intent, see the quirk below), when the
       input is already signed, the infix is `.cosign`.
     - Save (6.2.3) and log INFO `El fichero se ha firmado correctamente` (.3) with the output path.
   - **COSIGN** (`massiveCosignOperation`), for each file:
     - The data is unreadable → `allOK=false`, no log entry.
     - `defaultSigner.isSign(data)` → **cosign** with the default signer.
     - Otherwise, when `originalFormat` ("respetar formato original"):
       - if PDF, ODF or OOXML recognises the file as a valid data file, use that signer, and cosign when
         `isSign`, otherwise sign;
       - else if any signer recognises it as a signature (`AOSignerFactory.getSigner(data)`), cosign with
         that signer;
       - else sign with the default signer.
     - Otherwise (no `originalFormat`), sign with the default signer.
     - Sign uses the same MIME/OID and explicit-hash logic as SIGN, but the explicit decision reads `mode`
       from `signConfig`.
     - Errors: `No ha sido posible cofirmar el fichero: <msg>` (.11) or
       `No ha sido posible firmar el fichero de datos: <msg>` (.13), both SEVERE; OOM gives .8.
     - Infix `.cosign` or `.sign`. Log INFO `Se ha operado correctamente sobre el fichero (cosign|sign)`
       (.10).
   - **COUNTERSIGN_ALL / COUNTERSIGN_LEAFS**, for each file:
     - With `originalFormat`, the signer is the one detected from the file content. When none is found,
       SEVERE `No ha sido posible contrafirmar el fichero: <msg>` (.15) and skip.
     - The file must be a signature of that signer (`isSign`). Otherwise SEVERE
       `El fichero no es un fichero de firma con un formato reconocido` (.16).
     - `signer.countersign(data, algorithm, TREE|LEAFS, null, key, chain, signConfig)`. Errors:
       file not found → `No se ha encontrado el fichero` (.24); other errors → .15; OOM → .8.
     - Infix `.countersign`. Log INFO `El fichero se ha contrafirmado correctamente` (.20).
     - Plain data files are reported as errors, not "skipped silently" as the Javadoc claims.
7. The log is closed (6.2.4). The return value is `allOK`: `true` only when every file succeeded.
   `getSignedFilenames()` returns the absolute output paths written.

#### 6.2.3 Output naming and placement (`saveSignToDirectory`)

1. `relativePath := path.substring(len(inDir))` when `inDir` is set (directory mode). Otherwise (file-list
   mode) it is the path after its first separator.
   **Quirk:** with an absolute file list, `/home/u/a.txt` becomes `home/u/a.txt`, so the full tree is
   recreated under `outDir`.
2. `parent := outDir/relativePath`'s parent directory, created with `mkdirs` if needed. Failure logs SEVERE
   `Error al crearse la estructura de directorios del fichero` (.21) or `No se pudo crear la estructura de
   directorios del fichero` (.22) and skips the file.
3. `name := signer.getSignedName(fileName, infix)`, using the table in 6.1.4 with the infix (`.signed`,
   `.cosign`, `.sign`, `.countersign`) in place of `_signed`. Examples:
   - `doc.txt` (CAdES sign) → `doc.txt.signed.csig`;
   - `doc.pdf` (PAdES sign) → `doc.signed.pdf`; a signed PDF → `doc.cosign.pdf`;
   - `f.xml` (XAdES) → `f.xml.signed.xsig`;
   - cosigning `a.csig` → `a.csig.cosign.csig`;
   - countersigning → `a.xsig.countersign.xsig`;
   - `x.docx` → `x.signed.docx`.
4. **Collision:** while the file exists and overwrite is off, the name becomes
   `getSignedName(fileName, infix + "(" + i + ")")` for `i = 1, 2, …`. Examples: `doc.txt.signed(1).csig`,
   `doc.signed(2).pdf`.
5. **Path-traversal guard:** the canonical target must be inside the canonical `parent`. Otherwise SEVERE
   `La ruta del fichero no apuntaba dentro del directorio padre` (.23) and skip.
6. Write the bytes. A write error is logged as `.22` (misleading text), but the path is still recorded as
   written (quirk).

#### 6.2.4 Log / report (`DefaultLogHandler`)

- **File:** `result.log` in the output directory, or `logPath`. It is overwritten on every run. Encoding is
  the platform default.
- **Record:** `"\r\n" + LEVEL + ": " + message + " - " + (outputPath ?? inputPath ?? "")`, where `LEVEL` is
  `INFO`, `WARNING` or `SEVERE` (non-localised Java level names). Any level other than INFO or WARNING is
  printed as SEVERE.
- **Footer** (on close):
  `"\r\n\r\n" + "Advertencias emitidas" + ": " + warnCount + "\r\n" + "Errores emitidos" + ": " + errorCount`.
  The texts are `DirectorySignatureHelper.25` and `.26`. The counters are reset after closing.
- The level constants in `LogHandler` are `LEVEL_INFO=800`, `LEVEL_WARNING=900`, `LEVEL_SEVERE=1000`.
- Messages come from `massivesignmessages.properties` (Spanish default) and
  `massivesignmessages_gl_ES.properties` (Galician). The bundle exists twice, at the classpath root and
  under `massivesignmessages/`. It is loaded once with the default locale; other languages fall back to
  Spanish.

Example `result.log`:
```

INFO: El fichero se ha firmado correctamente - /out/sub/doc.txt.signed.csig
WARNING: El fichero no puede ser firmado con la configuración de firma actual - /in/foto.png
SEVERE: No ha sido posible firmar el fichero - /in/roto.pdf

Advertencias emitidas: 1
Errores emitidos: 1
```

#### 6.2.5 `hashesMassiveSign(hashes[], keyEntry, configuredSigner, config)`

This signs pre-computed Base64 hashes:
- `config` must have `format` and `mode`. A configured signer of a different class than the default gives
  `ClassCastException`.
- `headless=true` and `precalculatedHashAlgorithm=<digest of algorithm>` are set. XAdES and XMLDSig also get
  `mimeType=hash/<digest lowercase>`.
- Returns the Base64 signatures. A bad Base64 hash gives `AOException` code `600601`
  "Se ha proporcionado un hash no valido para la firma explicita".

#### 6.2.6 `MassiveSignatureHelper` (item-by-item API)

Configured with a `MassiveSignConfiguration`:
- `keyEntry`;
- `massiveOperation`, default `SIGN`;
- `algorithm`, default `SHA512withRSA`;
- `mode`, default `explicit`;
- `defaultFormat` and `signatureFormat`, default `CAdES`;
- `originalFormat`, default `true`;
- `extraParams`, cloned on set and on get.

Methods:
- `setSignatureFormat(f)`: switches the signer used for SIGN. An unknown format falls back to the default
  with a warning.
- `signData(bytes)`, `signFile(uri)`, `signHash(bytes)`: each returns the result or `null` and appends one
  human-readable entry to an in-memory log. Entries: `MassiveSignatureHelper.0`–`16`, e.g.
  `Operación sobre fichero correcta`, `Error en la operación sobre fichero - <msg>`.
- `signHash` supports SIGN only. COSIGN and COUNTERSIGN fail with "no es una operacion valida", and so do
  PAdES, ODF, OOXML and FacturaE.
- COSIGN and COUNTERSIGN use the default signer unless `originalFormat` is set; then the specific (PDF, ODF
  or OOXML) or detected signer is used. When `originalFormat` is false, the input must be a signature of the
  default format.
- `getCurrentLogEntry()` returns the last entry. `getAllLogEntries()` returns all entries joined with
  `\r\n` and trimmed.
- `disable()` and `isEnabled()`.

#### 6.2.7 Library quirks to be aware of

- `ODF_SIGNER = "es.gob.afirma.signers.odf.AOODFSSigner"` (typo, should be `AOODFSigner`), so signed ODF
  files never get the `.cosign` infix under SIGN.
- `XMLDSIG_SIGNER` is referenced although XMLDSig is not offered by AutoFirma.
- Static `MessageDigest` instances are shared, not thread-safe, and stick to the first algorithm used
  (`MassiveSignatureHelper.digest`).
- The `null/result.log` path and the always-truncated log (6.2.2 step 4).
- **Rust recommendation:** if a "sign folder" feature is offered (CLI or GUI), adopt the 6.1 desktop naming
  (`_signed`, `(n)` collision index, mirrored subdirectories, `massiveOverride`). Optionally emit a
  `result.log` in the 6.2.4 format as an opt-in report.


## 7. Plugins (to be reimplemented as built-in features)

AutoFirma has a small Java plugin system ("Gestionar plugins") through which two *official* plugins are distributed separately from the main installer:

| Plugin (internal name) | Title shown | What it adds | Module |
|---|---|---|---|
| `hash` | "Huellas digitales" | Menu, CLI commands `createdigest` / `checkdigest`, Windows Explorer context menus to compute/verify digests of files and directories | `afirma-simple-plugin-hash` (+ `afirma-simple-plugin-hash-exe`, VB.NET helper sources) |
| `validate_certs` | "Validación de certificados" | A "Validar certificado de firma" button on the signature-result screens that checks the signing certificate by OCSP/CRL | `afirma-simple-plugin-validatecerts` |

The Rust reimplementation cannot load Java JARs, so the recommendation (§7.8) is to implement both plugins as **built-in features** and keep the plugin *hook points* only as internal extension seams. Everything below documents the original behaviour precisely so parity (file formats, CLI syntax, registry entries) can be preserved.

### 7.1 Plugin package format

A plugin is a **single JAR (or ZIP) file**. Dependencies must be shaded into it: the manager copies exactly one file.

1. The JAR declares exactly one implementation of `es.gob.afirma.standalone.plugins.AfirmaPlugin` through the Java `ServiceLoader` file `META-INF/services/es.gob.afirma.standalone.plugins.AfirmaPlugin` (one line with the FQCN, e.g. `es.gob.afirma.plugin.hash.HashPlugin`).
   - 0 implementations → error `530002` "No se encontró ningún plugin en los archivos".
   - more than 1 → error `530003` "No se permite la carga simultánea de varios plugins".
   - malformed service file / class error → `530001` "Se han encontrado plugins mal definidos en el fichero importado".
2. A descriptor named `plugin.json` must exist **in the same package directory as the plugin class**: resource path `/<package of the AfirmaPlugin class with '.'→'/'>/plugin.json` (e.g. `/es/gob/afirma/plugin/hash/plugin.json`). Read as UTF-8 JSON (`javax.json`).

#### 7.1.1 `plugin.json` schema (`PluginInfoLoader`)

| JSON path | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `info` | object | yes | – | Basic info. |
| `info.name` | string | **yes** | – | Internal name (install directory name, identity for equality / upgrade). Never shown to the user. Must stay constant across versions. |
| `info.title` | string | **yes** | – | Human readable name (shown in the plugin list, configuration dialog title). Missing `name` or `title` → `PluginException("El plugin no define la informacion basica necesaria ('name' y 'title')")`. |
| `info.version_code` | int | no | `1` | Integer version; written to the `installed` file. **Never compared** (no upgrade/downgrade logic). |
| `info.version` | string | no | `"1.0"` | Display version. |
| `info.description` | string (HTML allowed) | effectively **yes** (`getString` without default → NPE → `PluginException "Se ha encontrado un error en el fichero /plugin.json"`) | – | Shown in the info pane (inside `<span>`; HTML such as `<br>` is rendered). |
| `info.authors` | string[] | no | null | Shown as "Autores:" list. |
| `info.contacts` | string[] | no | null | Shown as "Contacto:" list. |
| `info.configuration_panel` | string (FQCN) | no | null | Class extending `ConfigurationPanel` (a Swing `JPanel`); if present, the "Configurar" button appears. |
| `permissions` | string[] | no | `[]` | Permission names (case-insensitive, see §7.1.2). Unknown names are logged ("Permiso no reconocido") and ignored. Duplicates removed; sorted by permission order. |
| `inline_processor` | string (FQCN) | no | null | Class extending `SignDataProcessor` with a public `(int protocolVersion)` constructor (§7.2.5). |
| `menu` | object | no | null | Menu added to the main menu bar (§7.2.3). Must have `title` and (`items` or `action`) else `PluginException("Se han encontrado menus del plugin mal definidos")`. |
| `menu.title` | string | yes | – | Menu label. |
| `menu.action` | string | alt. | – | Stored as `dialogClass`; **never used** by the UI (and a top-level menu with only `action` makes `MainMenu.addSubMenus` iterate a null list → crash). *Gotcha.* |
| `menu.items[]` | object[] | alt. | – | Each item: `title` (req.) and `items` (sub-menu, recursive) or `action` (FQCN of a `PluginAction` subclass). Missing → `"Se han encontrado sub-menus del plugin mal definidos"`. If both are present, `items` wins. |
| `buttons[]` | object[] | no | null | Buttons injected in app screens (§7.2.2). Each needs (`title` or `icon`), `action`, `window`; otherwise `PluginException`. |
| `buttons[].title` | string | one of title/icon | null | Button text. |
| `buttons[].icon` | string | one of title/icon | null | Resource path **without leading slash**, loaded through the plugin class loader (e.g. `es/gob/afirma/plugin/certvalidation/certificate_16.png`). |
| `buttons[].tooltip` | string | no | null | Tooltip. |
| `buttons[].accesible_description` | string (sic, one "s") | no | null | Accessible description (screen readers). |
| `buttons[].window` | string | yes | – | Target screen, case-insensitive: `input` or `input_data`, `single_result`, `multi_result`, `visor`. Any other value → button silently never shown. |
| `buttons[].action` | string | yes | – | FQCN of a `PluginAction` subclass with public no-arg constructor; instantiated at load time (error `530006` "El plugin definió una clase de acción errónea" if invalid; `530004`/`530005` if action/window missing). |
| `commands[]` | object[] | no | null | CLI sub-commands. Each: `name` (req.), `action` (req., FQCN of a `PluginCommandAction` subclass), `description` (effectively req.). |

#### 7.1.2 Permissions (`Permission` enum)

| Name | Order | Spanish label (`permission.X` / `permission.X.desc` in `simpleafirmamessages`) | What it gates |
|---|---|---|---|
| `INSTALL` | 1 | "Instalación": "Permiso para hacer cambios en el equipo durante la instalación del plugin." | Calls to `install()` on install **and** `uninstall()` on removal. |
| `RESET` | 3 | "Reinicio": "Permiso para reiniciar la aplicación." | After install/uninstall the user is offered to restart AutoFirma. (Note: `AfirmaPlugin.reset()` itself is called for **all** plugins regardless of this permission.) |
| `PRESIGN` | 4 | "Preprocesado": "Permiso para procesar los datos antes de las operaciones de firma." | `preSignProcess()` hook. |
| `POSTSIGN` | 5 | "Postprocesado": "Permiso para procesar las firmas después de su generación." | `postSignProcess()` hook. |
| `BUTTONS` | 6 | "Nuevos botones": "Permisos para agregar botones a la interfaz de la aplicación." | `buttons[]`. |
| `MENU` | 7 | "Nuevo menú": "Permisos para agregar un menú a la interfaz de la aplicación." | `menu`. |
| `COMMANDS` | 8 | "Nuevos comandos": "Permisos para agregar nuevos comandos ejecutables por línea de comandos." | `commands[]` dispatch. |
| `INLINE_PROCESS` | 9 | "Firma en línea": "Permisos para modificar el proceso de firma cuando se solicite desde el navegador." | `inline_processor`. |

The message bundle also defines `permission.UNINSTALL` ("Desinstalación"), which does not exist in the enum (would be ignored with a warning).

### 7.2 Plugin API and hook points (`afirma-simple-plugins`)

#### 7.2.1 `AfirmaPlugin` lifecycle hooks

| Hook | Default | Called from | When / semantics |
|---|---|---|---|
| `install()` | no-op | `PluginsManager.installPlugin` | Once, right after the JAR is copied and loaded, only if `INSTALL` permission. Runs with the privileges of the AutoFirma process (admin only if AutoFirma was launched elevated). Exception → the plugin is uninstalled again and error `ERROR_IN_PLUGIN` shown (a `PluginControlledException` message is shown to the user). |
| `uninstall()` | no-op | `PluginsManager.uninstallPlugin` | On removal (and when replacing an older version), only if `INSTALL` permission. Exceptions are logged and ignored. |
| `preSignProcess(byte[] data, String format) → byte[]` | returns `data` | `SignPanelSignTask.pluginsPreProcess` | **GUI signing only** (single and multi-file signing from the main window), once per input file, before signing. Plugins are chained in load order (output of one = input of next). `format` = signature format name (`AOSignConstants` names, e.g. `"CAdES"`, `"PAdES"`, `"XAdES"`). |
| `postSignProcess(byte[] signature, String format, Certificate[] certChain) → byte[]` | returns `signature` | `SignPanelSignTask.pluginsPostProcess` | GUI signing only, once per generated signature, before saving. Chained. |
| `reset()` | no-op | `SignPanelSignTask.pluginsReset` | After the whole GUI signing run (single or massive) finishes, for every loaded plugin (no permission check). |
| `getInlineProcessor(int protocolVersion)` | instantiates `inline_processor` class once (cached) | protocol `sign` / `signandsave` | See §7.2.5. |
| `buildConfigurationPanel()` | instantiates `configuration_panel` class | Plugin configuration dialog | §7.4.3. |
| `getConfig()` | – | plugin code | Returns stored `Properties` (§7.2.7). |

Error handling of pre/post/reset hooks (GUI): a `PluginControlledException` shows its message in a warning dialog titled "Error" (`SimpleAfirma.7`) and processing **continues** with the unmodified data and with the next plugin; any other exception shows `SignPanel.111` "El plugin %0 ha devuelto un error al procesar los datos de entrada: %1" / `SignPanel.112` "...al procesar la firma generada: %1" / `SignPanel.115` "...al reiniciarse para permitir nuevas firmas: %1" (ERROR dialog) and continues. If the plugin list cannot be loaded: `SignPanel.113` / `SignPanel.114` warning and signing proceeds without plugins.

Pre/post processing is **not** applied to command-line signing, browser (protocol) signing or batch signing; browser requests can only be customised through inline processors. The bundled help (`MenuPlugins.html`) states this explicitly.

#### 7.2.2 UI actions and target screens

`PluginAction` (abstract): `start(Window parent)` (default no-op) plus protected `getConfig()` / `saveConfig(Properties)`. Two specialisations receive context:

| `window` value | Screen (Java class, see §2) | Action invoked | Data passed |
|---|---|---|---|
| `input` / `input_data` | Sign screen after loading file(s) (`SignPanel`) | `DataProcessAction.processData(InputData[], Window)` if the action is a `DataProcessAction`, else `start(Window)` | One `InputData` per loaded file: `dataFile` (File), `signatureFormat` (format name currently selected). |
| `single_result` | Single-signature result screen (`SignDetailPanel`) | `SignatureProcessAction.processSignatures(OutputData[], X509Certificate signingCert, Window)` or `start` | One `OutputData`: `dataFile` = saved signature file, `signatureFormat`, `certs` = distinct signer certificates (first cert of every node of the signature tree, de-duplicated by serial number); `signingCert` = certificate the user just signed with. `success` not set (false). |
| `multi_result` | Massive-signature result list (`SignResultListPanel`) | same | One `OutputData` per signed file (`dataFile` = signature file, `signatureFormat`); `certs` not set; `signingCert` = certificate used. |
| `visor` | Signature viewer (`VisorPanel`) | same | One `OutputData` (`dataFile` = viewed signature file, `signatureFormat` from the analysed signature, `certs` as in single_result); **`signingCert` = null**. |

Buttons are rendered (in declaration order, plugins in load order) in a panel below a horizontal separator at the bottom of the screen (FlowLayout, left-aligned); the panel is hidden when there are no buttons. Text = `title`, icon = `icon`, tooltip, accessible description. Each click runs the action **on a new background thread** (not the UI thread). The panel is rebuilt (`refreshPluginButtonsContainer`) when the plugin manager dialog closes.

#### 7.2.3 Menus

For each loaded plugin with `MENU` permission and a `menu`, a top-level `JMenu` titled `menu.title` is appended to the menu bar **after "Idioma" and before "Ayuda"** (main menu order: "Archivo" | "Herramientas" | "Idioma" | *plugin menus* | "Ayuda"). Items with children become sub-menus; leaves become menu items. Clicking a leaf: `PluginLoader.getPluginAction(actionClass)` creates a **new instance** of the action (using the class loader of the plugin that declared that class; first declaration wins in the static map `classLoaderForPlugin`) and calls `start(parentFrame)`. Errors → "Ocurrió un error inesperado al ejecutar la acción." (`SimpleAfirma.52`). The menu bar is built once at startup: newly installed plugin menus appear only after restart.

#### 7.2.4 Command-line commands

`PluginCommandAction(String command)`: `getHelpText()` (abstract), `start(String[] args)` (final: strips `args[0]` if it equals the command, case-insensitive) → `process(String[] args) → String`.

Dispatch (`CommandLineLauncher`, see §5): if `args[0]` (lower-cased) is not a built-in command, the loaded plugins **with `COMMANDS` permission** are searched for a command with that name (case-insensitive); the action class is instantiated fresh and `start(args)` called.
- Returned non-null string → printed to stdout, exit code `0`.
- `PluginControlledException` / `UnsupportedOperationException` → its message printed, exit code `-1` (255).
- Any other exception (including `IllegalArgumentException` from parameter parsing) → `"Error no reconocido: %0"` (`CommandLineLauncher.50`), exit `-1`.
- If `-xml` appears in args, error messages are wrapped in the XML response format (§5).
- Unknown command → `"Comando no reconocido: %0"` + general syntax, exit `-1`.
- The general help (`AutoFirma -help`) lists, after the built-in commands, a section `CommandLineLauncher.126` with every plugin command as `  <name>\t (<description>)` — for **all** loaded plugins, even those lacking `COMMANDS` permission (quirk).

#### 7.2.5 Inline (browser-protocol) processors

`SignDataProcessor` (abstract, constructed with the protocol **major** version):
- `checkTrigger(SignOperation) → boolean`: whether this processor handles the request.
- `setServerCipher(ServerCipher)`: cipher for the response when the request carried a cipher key.
- `preProcess(SignOperation) → List<SignOperation>`: expands one browser request into N sign operations (N>1 makes the signing run in "massive" mode).
- `postProcess(List<SignResult>, SignOperation) → StringBuilder`: builds the protocol response text.
- `isErrorsAllowed()` (default false): if true, a failing operation is skipped instead of aborting.

Selection (`ProtocolInvocationLauncherSign.selectProcessor` for `sign`, and the equivalent in `ProtocolInvocationLauncherSignAndSave`): iterate loaded plugins with `INLINE_PROCESS`; first processor whose `checkTrigger` is true wins; otherwise the built-in `NativeSignDataProcessor`. Quirk: in `sign`, a plugin with `INLINE_PROCESS` but no `inline_processor` class makes the loop **stop** (`break`) and fall back to native; `signandsave` just skips it.

`NativeSignDataProcessor` (the default and the only one that matters for the reimplementation): `preProcess` returns `[operation]`; `checkTrigger` always true; `postProcess` uses only the first result and returns `CERT|SIGNATURE[|EXTRADATA]` where `|` is the literal separator; without cipher: `Base64(cert DER)` and `Base64(signature)` (URL-safe alphabet), and for protocol version ≥ 3 when extra data exists (e.g. the name of the file the user picked) a third field `Base64(UTF-8 JSON {"k": "v", ...})`; with cipher: each field is the cipher's own Base64 output. The protocol itself is specified in the protocol spec, not here.

`SignOperation`: `cryptoOperation` (`SIGN`/`COSIGN`/`COUNTERSIGN`), `data`, `format`, `algorithm`, `extraParams` (Properties), `anotherParams` (Map). `SignResult`: `signature`, `certificate` (DER), `extraData` (Properties; setter is misnamed `setDataFilename`).

`DataCipher` interface (`cipher(byte[])→String`, `decipher(String)→byte[]`) exists in the API but is **unused** anywhere.

#### 7.2.6 `UIFactory` (services offered to plugins)
- `getWaitingDialog(Component parent, String message, String title)` → reflectively builds `es.gob.afirma.standalone.ui.CommonWaitDialog(Frame, message, title)` (indeterminate wait dialog; see §3).
- `getDefaultDialogIcon()` → `DesktopUtil.getDefaultDialogsIcon()` (app icon for dialogs).

#### 7.2.7 Plugin configuration storage

Two near-duplicate classes store a plugin's `Properties` in **`java.util.prefs` user node for the plugin class's package** (`Preferences.userNodeForPackage(pluginClass)`), e.g. node `/es/gob/afirma/plugin/hash` for the hash plugin (stored like the rest of the app's preferences, see §4; on Windows: `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\plugin\hash`, Java-encoded: upper-case letters are escaped as `/x`, e.g. value name `create/Hash/Algorithm`; Linux `~/.java/.userPrefs/es/gob/afirma/plugin/hash/prefs.xml`):
- `PluginPreferences` (API, used by `AfirmaPlugin.getConfig()` and `PluginAction.getConfig()/saveConfig()`): **a global singleton**; the node is fixed by the first plugin that calls it (bug if several plugins have config). `saveConfig` tries to clear old data by removing *child node names* (not keys), so stale keys are never removed, then `put`s every property and `flush()`es.
- `PluginsPreferences` (manager, used by the "Configurar" dialog): one instance per internal name; `saveConfig` (no flush), `recoverConfig`, `removeConfig()` (removes the whole node; called when the user removes the plugin).
- The Windows NSIS uninstaller deletes `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\plugin` (all plugin configs).

### 7.3 Plugin manager (`afirma-simple-plugins-manager`)

#### 7.3.1 Plugin directory

`SimpleAfirma.getPluginsDir()` = `<base>/plugins`, where `<base>` = `DesktopUtil.getAlternativeDirectory()`:

| OS | Plugins directory |
|---|---|
| Windows | `%ALLUSERSPROFILE%\Autofirma\plugins` (e.g. `C:\ProgramData\Autofirma\plugins`) — **shared by all users** |
| Linux | `~/.afirma/Autofirma/plugins` |
| macOS | `~/Library/Application Support/Autofirma/plugins` |
| other | `<directory of the running JAR>/plugins` |

Layout:
```
plugins/
  installed                 # UTF-8 text, one line per plugin: "<internalName>:<versionCode>\n"
  <internalName>/
    <original jar file name>.jar
```
Directories and files are created with world read/write/execute (`AOFileUtils.setAllPermissions`: `setReadable/Writable/Executable(true,false)` plus copying ACLs on Windows). *Security gotcha:* on Windows the shared, world-writable directory lets any local user plant code that every user's AutoFirma will load. When the last plugin is removed the whole `plugins` directory is deleted.

#### 7.3.2 Loading (`PluginsManager.getPluginsLoadedList`, `PluginLoader.loadPlugin`)

At GUI startup ("Cargando plugins", before building the main window) and lazily in CLI mode:
1. If `plugins/installed` exists, parse each non-empty line `name:versionCode` (split on `:`; malformed lines skipped with a warning).
2. For each entry, list readable regular files in `plugins/<name>/`; none → `INSTALLED_PLUGIN_NOT_FOUND` (`230206`), the plugin is skipped (the `installed` file is not rewritten).
3. Create a `URLClassLoader` over those files (parent = app class loader), `ServiceLoader` the `AfirmaPlugin` implementation (exactly one), read `plugin.json`, register every action class name (buttons, commands, menu leaves) in the static map action→plugin, instantiate button actions, `setInfo`, `setClassLoader`.
4. Failure of the whole list → startup warning dialog title "Advertencia" (`SimpleAfirma.48`), text "No se han podido cargar los plugins en la aplicación." (`SimpleAfirma.4`).

The loaded list is cached in memory (`getPluginsLoadedList(force=false)`).

#### 7.3.3 Installation flow (GUI only; `PluginsManagementHandler.addPlugin`)

1. File chooser: title "Cargar plugin" (`PluginsManagementHandler.3`), extensions `jar`, `zip`, description "Plugin de Autofirma".
2. **Signature check** `JarVerifier.verify(file)`:
   - File size ≥ 100 000 000 bytes → `IOException` → error `530007` "El fichero cargado no es válido para ser importado".
   - Open as signed JAR with verification; no manifest → `SecurityException`.
   - Read every entry (except directories and anything whose name contains `META-INF`); each must have code signers, and all entries must be signed by exactly the same signer set; otherwise `JarNoSignedException`.
   - **No trust anchor is checked**: any signer certificate (even self-signed or expired) is accepted technically; trust is delegated to the user.
   - Outcomes:
     - Unsigned/partially signed → confirm (YES/NO, warning) "El plugin no está firmado o no está completamente firmado. Instálelo sólo si confía en su origen.\n¿Desea continuar con la instalación?" title "Plugin sin firmar".
     - `SecurityException` (bad signature/no manifest) → confirm (YES/NO, error icon) "La firma del plugin no es válida. Instálelo sólo si confía en su origen.\n¿Desea continuar con la instalación?" title "La firma del plugin contiene errores".
     - File not found → error `530009` "No se ha encontrado el fichero de plugin"; other errors → `530007`.
     - Signed OK → confirm dialog title "Certificado de firma" containing `CertificateConfirmPanel`: "El plugin se encuentra firmado por:" then one row per signer: " - <CN>" (+ "(caducado)" if `notAfter` < now) and a button "Descargar certificado" (icon `certificate_16.png`; accessible description "Descargar certificado de %0" / "... (caducado)") that saves the signer's leaf certificate DER via a save dialog (title "Guardar certificado", default name `certificado_plugin.cer`, filter "Certificado" `*.cer`; error "Error al guardar el certificado"), then "¿Desea continuar con la instalación?" YES/NO.
3. Trial load of the plugin from the selected file (validates `plugin.json`, service, actions); errors shown by error code (§7.3.5); the class loader is then closed.
4. If the plugin declares ≥1 permission: `PermissionsDialog` (modal, 400×min(500, 0.8·screenH), title "Información del plugin", accessible description "Diálogo de información del plugin") showing a scrollable bordered list titled "Permisos requeridos por el plugin" with `" - <b>Label:</b> description"` per permission; buttons "Conceder permisos" / "Cancelar" (ESC = cancel except on macOS). Cancel aborts.
5. `PluginsManager.installPlugin(file, internalName)`:
   - create `plugins/` (and parent) if needed;
   - if `plugins/<internalName>` already exists → `PluginInstalledException` → the UI asks (YES/NO/CANCEL) "Ya existe una versión instalada del plugin \"%0\".\n¿Desea sustituirla por la nueva versión?" title "Instalar plugin"; on YES the old one is removed (full uninstall incl. `uninstall()` hook if it is in the loaded list; otherwise its directory is force-deleted; failure → `230203`) and installation retried;
   - copy the file to `plugins/<internalName>/<file name>`; load it (failure → directory deleted, error);
   - if `INSTALL` permission → `install()` (failure → rollback uninstall, error);
   - append `"<internalName>:<versionCode>\n"` to `plugins/installed`; add to the loaded list.
6. If `RESET` permission → restart prompt (§7.3.6).
7. The list is refreshed, the new plugin selected and its info shown.

#### 7.3.4 Removal flow

Select plugin → "Eliminar" → confirm (YES/NO/CANCEL) "Se va a desinstalar el plugin \"%0\". ¿Desea continuar?" title "Desinstalar plugin" → `uninstall()` hook (if `INSTALL` permission; errors ignored) → remove from loaded list → close class loader → delete `plugins/<internalName>/` → rewrite `installed` (or delete the whole `plugins/` dir if empty) → remove the plugin's preference node (`PluginsPreferences.removeConfig`) → if `RESET` permission, restart prompt. Error → `UNINSTALL_PLUGIN_ERROR`.

#### 7.3.5 Error codes (`PluginManagerError`, `SimpleErrorCode`)

| Code | Constant | Message |
|---|---|---|
| 230200 | `Internal.PLUGIN_ERROR` | "Error desconocido con el plugin" (fallback for unknown errors) |
| 230201 | `Internal.UNINSTALL_PLUGIN_ERROR` | "Ocurrió un error al desinstalar el plugin" |
| 230202 | `Internal.ERROR_IN_PLUGIN` | "El propio plugin devolvió un error durante su instalación" |
| 230203 | `Internal.CANT_REMOVE_LOADED_PLUGIN` | "Ha ocurrido un error al eliminar el plugin anterior" |
| 230204 | `Internal.PLUGIN_DIRECTORY_ERROR` | (Java text says "already installed"; UI text "Ha ocurrido un problema con el directorio de instalación") |
| 230205 | `Internal.PLUGIN_LOAD_ERROR` | "Ha ocurrido un error al intentar cargar el plugin" |
| 230206 | `Internal.INSTALLED_PLUGIN_NOT_FOUND` | "No se encontraron los ficheros de un plugin previamente instalado" |
| 530001 | `Functional.MALFORMED_PLUGIN_SERVICE` | "Se han encontrado plugins mal definidos en el fichero importado" |
| 530002 | `Functional.NO_PLUGIN_FOUND` | "No se encontró ningún plugin en los archivos" |
| 530003 | `Functional.MULTIPLE_PLUGINS_FOUND` | "No se permite la carga simultánea de varios plugins" |
| 530004 | `Functional.BUTTON_NO_ACTION` | "El plugin no ha definido acción para un botón" |
| 530005 | `Functional.BUTTON_NO_WINDOW` | "El plugin no ha definido la ventana en la que debe aparecer un botón" |
| 530006 | `Functional.INVALID_ACTION_CLASS` | "El plugin definió una clase de acción errónea" |
| 530007 | `SimpleErrorCode.Functional.INVALID_PLUGIN_FILE` | "El fichero cargado no es válido para ser importado" |
| 530008 | `Functional.ALREADY_INSTALLED_PLUGIN` | "El plugin seleccionado ya se encuentra instalado" |
| 530009 | `SimpleErrorCode.Functional.PLUGIN_FILE_NOT_FOUND` | "No se ha encontrado el fichero de plugin" |

UI messages are looked up as `PluginManagementError.<code>`. *Quirk:* the bundle has keys `PluginManagementError.240000..240004` while the internal codes are `2302xx`, so internal errors resolve to missing keys; a reimplementation should simply map each code to the texts above.

#### 7.3.6 Restart prompt (`resetApplication`)
If the restart command can be determined (`DesktopUtil.getResetApplicationCommand`: macOS `.app` executable wrapping the JAR, `java -jar <jar>`, or the Windows `.exe`): confirm YES/NO (warning) "La operación ha finalizado correctamente, pero es necesario reiniciar la aplicación para\nque los cambios surtan efecto. ¿Desea que se reinicie la aplicación?" title "Reiniciar Autofirma" → spawn new instance and `System.exit(0)`. Otherwise an info dialog "La operación ha finalizado correctamente. Reinicie la aplicación para que los cambios\nsurtan efecto.".

### 7.4 Plugin management UI ("Herramientas → Gestionar plugins")

#### 7.4.1 Entry point
Menu "Herramientas" (`MainMenu.32`) → "Gestionar plugins" (`MainMenu.37`), accelerator **Ctrl/Cmd+G**, mnemonic G. Opens `PluginsManagementDialog` (modal, title "Gestionar plugins", 600 × min(550, 0.8·screen height), centred on the main window). On close, the current screen's plugin button panel is refreshed.

#### 7.4.2 Layout (`PluginsManagementPanel`)
- Left (250×500 preferred): titled border "Plugins instalados" with a single-selection list of plugin titles; below it buttons "Agregar" (mnemonic A, accessible "Instala un nuevo plugin") and "Eliminar" (mnemonic E, accessible "Elimina el plugin seleccionado"). On macOS both scrollbars are always visible.
- Right: titled border "Información del plugin": scrollable, focusable HTML pane (border highlighted black when focused):
  ```
  <b>Versión:</b>   <version>
  <b>Autores:</b>   - <author>... (only if any)
  <b>Contacto:</b>  <contact>...  (only if any)
  <b>Descripción:</b> <description HTML>
  ```
  and, bottom-right, a "Configurar" button visible only when the selected plugin declares `configuration_panel`.
- Bottom: "Cerrar" (accessible "Cierra el panel de gestión de plugins").
- The list is filled on a background thread; the first plugin is pre-selected. ESC closes the dialog (not on macOS).
- Load failure → error "No se ha podido cargar la lista de plugins." (`PluginsManagementHandler.8`).

#### 7.4.3 Configuration dialog (`PluginConfigurationDialog`)
Title = plugin title; content = plugin's `ConfigurationPanel` (`init(Properties)` receives the stored config) + buttons "Aceptar" / "Cancelar"; resizable, centred on screen. On "Aceptar" the dialog closes and `getConfiguration()` is persisted via `PluginsPreferences.saveConfig`. Panel build error → "El diálogo de configuración del plugin devolvió un error. Consulte\ncon el desarrollador como resolver el problema.". (Neither official plugin has a configuration panel.)

### 7.5 Hash plugin — "Huellas digitales" (`afirma-simple-plugin-hash`)

#### 7.5.1 Identity
- Class `es.gob.afirma.plugin.hash.HashPlugin`; `plugin.json`: `name` = `hash`, `title` = "Huellas digitales", `version_code` 1, `version` "1.0", authors ["Gobierno de España"], description "Plugin para el cálculo y la comprobación de hashes.<br><br>El componente permite generar ficheros de hashes con el hash de un fichero o de todos los ficheros de un directorio. También permite comprobar que un fichero de hashes es válido seleccionando el fichero o directorio a partir del cuál se generó.<br><br>El plugin permite realizar las nuevas operaciones tanto desde interfaces gráficos como desde línea de comandos."
- Permissions: `INSTALL`, `RESET`, `MENU`, `COMMANDS`.
- Menu:
  ```
  Huellas digitales
  ├── Fichero
  │   ├── Calcular huella digital            → CalculateHashFileAction  → §7.5.6 (a)
  │   └── Comprobar huella digital           → CheckHashFileAction      → §7.5.6 (c)
  └── Directorio
      ├── Calcular huella digital en directorio → CalculateHashDirAction → §7.5.6 (b)
      └── Comprobar huella digital en directorio→ CheckHashDirAction     → §7.5.6 (d)
  ```
- Commands: `createdigest` ("Creación de huellas digitales con interfaz gráfica"), `checkdigest` ("Comprobación de huellas digitales con interfaz gráfica"). (The descriptions in the shipped `plugin.json` are Latin-1 bytes inside a UTF-8 file → displayed with replacement characters; cosmetic bug.)
- All texts are Spanish only (`es/gob/afirma/plugin/hash/messages.properties`, no translations).

#### 7.5.2 Digest computation
- Algorithms offered in the GUI combos (order; first is default): `SHA-256`, `SHA-1`, `SHA-384`, `SHA-512`. The CLI accepts any JCA `MessageDigest` name via `-halgorithm` (default `SHA-256`).
- Files are read streaming in 25 MiB (`25*1024*1024` = 26 214 400 bytes) chunks (`DigestManager.SIZE_25MB`). No size limit (OutOfMemoryError handling exists only as a legacy message "El fichero es demasiado grande, no se puede generar la huella digital.").
- Hex encoding uses **upper-case** digits `0-9A-F`.

#### 7.5.3 Single-file digest formats

| Format (GUI label / CLI `-hformat`) | File extension | Content written |
|---|---|---|
| "Hexadecimal en ASCII (Base16)" / `hex` (**default**) | `.hexhash` | ASCII upper-case hex + literal suffix `h`, no newline. e.g. `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855h` (SHA-256 of empty file) |
| "Base64" / `b64` | `.hashb64` | Standard Base64 (`+/`, `=` padding), single line, no newline: `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=` |
| "Binario" / `bin` | `.hash` | Raw digest bytes. (CLI: only allowed with `-o`, else error "La generacion de la huella en binario requiere que se indique fichero de salida") |

Clipboard (GUI, checkbox "Copiar huella digital al portapapeles", default on): copies the text of the selected format; for Binario it copies hex+`h` instead.

#### 7.5.4 Directory traversal rules (`CreateHashAction`, `CheckHashAction`)
- Parallel traversal with a fork/join pool of 10 workers.
- Non-recursive: only regular files directly inside the directory. Recursive (`-r` / "Recursivo"): all files in subdirectories too. Symlinks follow Java `File.isFile()/listFiles()` semantics (followed).
- Skipped **files**: names containing `~$` (Office lock files) and names exactly equal to one of `.fseventsd`, `.Spotlight-V100`, `.Trashes`, `._.Trashes`, `.DS_Store`, `.desktop`, `thumbs.db`, `$Recycle.Bin` (case-sensitive; directory entries in that list are **not** skipped because the check applies only to files — quirk).
- Entry key = path of the file **relative to the selected directory**, using the **OS separator** (`\` on Windows, `/` elsewhere) → documents are not portable across OSes (quirk; recommendation: write `/`, accept both when reading).
- Errors: an unsupported algorithm or an I/O error on any file shuts the pool down; already-computed entries are kept and the document is still produced **without telling the user** (gotcha).
- Entry order in output = Java `HashMap` iteration order (effectively arbitrary); a reimplementation may sort.

#### 7.5.5 Directory digest documents

Default directory format: XML. Supported: XML (`.hashfiles`), TXT (`.txthashfiles`). A CSV generator exists but is unreachable (GUI maps `.csv` to XML; CLI rejects `csv`).

**XML (`.hashfiles`, `XmlHashDocument`)**, UTF-8, indented, with declaration; must validate against `afirma-simple/src/main/resources/schemas/folderhashes.xsd`:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<entries hashAlgorithm="SHA-256" recursive="true">
    <entry hash="Ez7piSk_knNjASgMbxTInVISAMF9zc7MowzSBwUzLUQ=" hexhash="133EE989293F92736301280C6F14C89D521200C17DCDCECCA30CD20705332D44h" name="sub/hola.txt"/>
    <entry hash="47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=" hexhash="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855h" name="vacio.txt"/>
</entries>
```
- Serialised by the JDK DOM transformer (indent on): attributes come out alphabetically (`hash`, `hexhash`, `name`), indentation is cosmetic; readers must not depend on either.
- `entries@hashAlgorithm`: XSD enumeration `SHA-1|SHA-256|SHA-384|SHA-512` (a CLI-created document with another algorithm will fail validation on check).
- `entries@recursive`: `true|false` (required).
- `entry@name` (required): relative path. `entry@hash` (required): **URL-safe Base64** (`-` `_`, with `=` padding) of the digest. `entry@hexhash` (optional in XSD, always written): upper-case hex + `h`.
- Loading: XSD validation, encoding taken from the XML declaration; for each entry decodes `hash` (URL-safe Base64) and `hexhash` (hex, optional trailing `h`); if both differ → **corrupted document** error (`CorruptedDocumentException`). (If `hexhash` is absent the Java code throws a generic format error; treat as optional in a robust reader.)

**TXT (`.txthashfiles`, `TxtHashDocument`)**, lines separated by CRLF:
```
;charset=UTF-8
;hashAlgorithm=SHA-256
;recursive=true
sub/hola.txt;133EE989293F92736301280C6F14C89D521200C17DCDCECCA30CD20705332D44
vacio.txt;E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
```
- Header lines start with `;` (`;charset=`, `;hashAlgorithm=`, `;recursive=`; other `;` lines ignored for forward compatibility). Hex has **no** `h` suffix here (reader accepts both).
- Reading: document must be > 30 bytes; if the first 30 bytes start with `;charset=` and contain `\r`, that charset is used to decode, else UTF-8. Each data line: split at the **first** `;` (path may not contain `;`); a line with `;` at position 0 or at the end → format error. Hex is not validated (garbage decodes silently).

**CSV (dead code, `CsvHashDocument`)**: `"<path>","<HEX>h"\r\n` per entry, no header; cannot be loaded.

**Format detection on load (`HashDocumentFactory.loadDocument`)**: by extension of the hash file: `xml`/`hashfiles` → XML, `txt`/`txthashfiles` → TXT. Quirks: a file without extension → NPE (error); when the declared format fails to parse (non-corruption error), the "fallback" loop returns an **empty, unparsed** document of the same class, so verification then reports every file as "file without hash". A reimplementation should sniff content (XML vs `;charset=` header) and fail clearly.

#### 7.5.6 GUI dialogs

All dialogs: modal, non-resizable, app icon, ESC closes (except macOS), button order reversed on macOS (Cancel before the action button), long work done in a background worker while a `CommonWaitDialog` is shown.

**(a) "Creación de huella digital" — `CreateHashFileDialog` (600×350)**
- "Fichero sobre el que calcular la huella digital" + read-only text field + "Examinar" (mnemonic E; chooser title "Seleccione el fichero para crear la huella digital", filter "Todos los ficheros (*.*)").
- "Algoritmo de huella digital": combo (default = pref `createHashAlgorithm` or `SHA-256`).
- "Formato de la huella digital": combo "Hexadecimal en ASCII (Base16)" / "Base64" / "Binario" (default = pref `createHashFormat` or hex).
- Checkbox "Copiar huella digital al portapapeles" (default = pref `createHashCopyToClipBoard`, default `true`).
- Buttons "Generar" (mnemonic G, disabled until a file is chosen; accessible "Pulse este botón para calcular y guardar la huella digital del fichero seleccionado") and "Cancelar" (mnemonic C).
- Generar: wait dialog (title "Generando", text "Generando huellas digitales") → digest → clipboard (if checked) → save dialog title "Guardar huella digital", default name `<input file name>.<ext>` (`hexhash`/`hashb64`/`hash`), filter "Huella digital (*.<ext>)". Cancelling the save keeps the dialog open; success closes it. Errors: "No ha podido generarse la huella digital." / "No se ha podido guardar la huella digital del fichero." (title "Error").

**(b) "Creación de huella digital de directorios" — `CreateHashDirDialog` (600×250)**
- "Directorio sobre el que calcular las huellas digitales" + read-only field + "Examinar" (mnemonic X; directory chooser; unreadable → "No se tienen permisos para leer el fichero").
- "Algoritmo de huella digital" combo (pref `createHashDirectoryAlgorithm`, default SHA-256).
- Checkbox "Recursivo" (mnemonic R; pref `createHashDirectoryRecursive`, default false).
- "Generar" (mnemonic G, enabled after choosing) / "Cancelar".
- Generar: wait dialog → compute all → save dialog "Guardar huellas digitales", default name `<dir name>.hashfiles`, filters "Huellas digitales en formato XML (*.hashfiles)" (first) and "Huellas digitales en formato TXT (*.txthashfiles)". **The format is decided by the chosen file's extension**: `.txthashfiles` or `.txt` → TXT; anything else (including `.csv`, no extension) → XML. Errors: "Error al almacenar el fichero de huellas digitales", "No ha podido generarse la huella digital.", "<html>El directorio contiene al menos un fichero demasiado grande.<br>No ha podido completarse el proceso.</html>".

**(c) "Comprobar huella digital" — `CheckHashFileDialog` (600×250)**
- "Fichero de datos" + field + "Examinar" (mnemonic E; title "Seleccionar fichero de datos").
- "Fichero que contiene la huella digital" + field + "Examinar" (mnemonic x; title "Seleccionar huella digital", filter "Huellas digitales (*.hash, *.hashb64, *.hexhash)").
- "Comprobar" (mnemonic C, enabled when both chosen) / "Cancelar" (accessible "Pulse este botón para cerrar el diálogo actual").
- Result: info "Las huellas digitales coinciden" (title "Huellas coincidentes") or warning "Las huellas digitales no coinciden" (title "Huellas no coincidentes"); error "No ha sido posible comprobar las huellas digitales". The wait dialog only appears for data files > 50 000 000 bytes. Dialog stays open after the result.

**(d) "Comprobar huella digital de directorio" — `CheckHashDirDialog` (600×250)**
- "Directorio" + field + "Examinar" (mnemonic X, directory chooser).
- "Fichero de huellas digitales" + field + "Examinar" (mnemonic E; filter "Fichero de huella digitales" `*.hashfiles`, `*.txthashfiles`).
- "Comprobar" (mnemonic R) / "Cancelar" (mnemonic C).
- Comprobar: wait dialog (title "Comprobando", "Comprobando huellas digitales") → verify (§7.5.8) → info "Las huellas digitales coinciden" (no errors) or warning "Errores encontrados en la verificación de huellas digitales" (title "Error") → **always** a save dialog for the report: title "Guardar informe de huellas digitales", directory = parent of the checked directory, default name `informe.hashreport`, filter "Informe de comprobación de huellas (*.hashreport)" → dialog closes. Errors: unsupported document "El fichero de huellas seleccionado no esta soportado."; corrupted "El fichero de huellas seleccionado esta corrupto o ha sido manipulado."; generic "No ha sido posible comprobar las huellas digitales".

#### 7.5.7 Single-file verification algorithm (`CheckHashFileDialog.checkHash`)
1. Read the whole hash file.
2. If `Base64.isBase64(bytes)` (all chars in `A-Za-z0-9+/=_-~\t\r\n`, `=` only in the last 2 positions, non-newline count multiple of 4) → decode as **standard** Base64.
3. Else if hex (`^[0-9a-fA-F]+$` with even length, or same plus trailing `h` with odd total length) → strip **the last character** and hex-decode. (Bug: an un-suffixed even-length hex string loses its last digit and fails; a robust reader should strip only a trailing `h`.)
4. Else treat as raw binary digest.
5. Algorithm inferred from digest length: 20 bytes → `SHA-1`; otherwise `"SHA-" + 8·len` (32→SHA-256, 48→SHA-384, 64→SHA-512; others fail as unknown algorithm → error).
6. Compute digest of the data file, compare byte-wise.
Gotchas: a trailing newline (e.g. hand-edited file) makes hex/base64 detection fail; a hex string whose length is a multiple of 4 and that has no `h` would be mis-detected as Base64.

#### 7.5.8 Directory verification and report
1. Load the hash document (§7.5.5). Algorithm and recursion are taken **from the document**.
2. Traverse the directory with the same rules (§7.5.4). For each file: relative path not in the document → `file_without_hash`; else compute and compare → `matching_hash` / `not_matching_hash`, and remove the path from the expected set.
3. Remaining expected paths → `hash_without_file`.
4. `hasErrors` = any of not_matching / hash_without_file / file_without_hash non-empty. (The hash document itself, if stored inside the checked directory, is reported as `file_without_hash`.)
5. Report XML (`.hashreport`, UTF-8; sections appear only if non-empty, in this order):
```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<entries hashAlgorithm="SHA-256" recursive="true">
    <matching_hash>
        <entry name="vacio.txt"/>
    </matching_hash>
    <not_matching_hash>
        <entry name="sub/hola.txt"/>
    </not_matching_hash>
    <hash_without_file>
        <entry name="borrado.txt"/>
    </hash_without_file>
    <file_without_hash>
        <entry name="nuevo.txt"/>
    </file_without_hash>
</entries>
```
The bundled `reportfolderhashes.xsd` declares a different element order and makes all four sections mandatory; it is never used and the generated reports do not validate against it (quirk).

#### 7.5.9 Hash preferences (`HashPreferences`, stored in the plugin prefs node, §7.2.7)

| Key | Type | Default | Edited by | Notes |
|---|---|---|---|---|
| `createHashAlgorithm` | string | `SHA-256` | file dialog algorithm combo | saved on change, persisted when dialog closes |
| `createHashFormat` | string | hex | file dialog format combo | stored as the **localized display text** (e.g. `Hexadecimal en ASCII (Base16)`); reader also accepts `hex`/`b64`/`bin`; unknown → hex |
| `createHashCopyToClipBoard` | `"true"/"false"` | `true` | clipboard checkbox | |
| `createHashDirectoryAlgorithm` | string | `SHA-256` | directory dialog combo | |
| `createHashDirectoryRecursive` | `"true"/"false"` | `false` | "Recursivo" checkbox | |

The check dialogs keep no preferences.

#### 7.5.10 Command line: `createdigest` / `checkdigest`

Invocation: `AutoFirma createdigest ...` / `AutoFirma checkdigest ...` (Windows console launcher `AutofirmaCommandLine.exe`, see §5). Parameters (`HashParameters`; option names are case-sensitive, lower-case):

| Option | Arg | Applies to | Meaning |
|---|---|---|---|
| *(positional first arg)* | path | both | Main file or directory. **Required** for `createdigest` (must be first); optional for `checkdigest` (taken only if it is the first arg and not an option). Must exist and be readable: "El fichero o directorio indicado no existe: %0" / "No hay permisos de lectura sobre el fichero o directorio indicado: %0". |
| `-i` | file | checkdigest | Hash file (`.hexhash`/`.hashb64`/`.hash` for a file, `.hashfiles`/`.txthashfiles` for a directory). Must exist/readable ("El fichero de entrada no existe: %0"). Duplicate → "Parametro duplicado: %0". |
| `-o` | file | both | createdigest: output file (else printed to stdout). checkdigest (directory): write the XML report there. Parent dir must be writable ("No hay permisos de escritura en el directorio especificado para el fichero de salida: %0"). |
| `-halgorithm` | name | createdigest | Digest algorithm (JCA name). Default `SHA-256`. |
| `-hformat` | `hex`\|`b64`\|`bin`\|`xml`\|`txt` | createdigest | Output format (lower-cased). File: hex (default), b64, bin. Directory: xml (default), txt. Wrong family → "No se ha indicado un formato de salida de huella digital de directorios valido: %0" / "...de fichero valido: %0"; unknown → "Formato de salida de huella digital no soportado: %0". |
| `-r` | – | createdigest | Recurse into subdirectories. |
| `-gui` | – | both | Use the graphical flow (dialogs) instead of console; the process then ends with `halt(0)` (exit code always 0). |
| `-d` | – | checkdigest | *Hidden*: with `-gui` and no positional path, ask the user for a **directory** instead of a file. |
| `-xml` | – | both | Parsed but ignored by the plugin (the launcher wraps error messages in XML when present). |
| `-help` | – | both | As first argument after the command: print help. `checkdigest` with no arguments also prints help (exit 0); `createdigest` with no arguments fails ("No se ha indicado ningun fichero o directorio", exit -1). |

Console behaviour:
- `createdigest FILE [-halgorithm A] [-hformat hex|b64|bin] [-o OUT]`: without `-o` prints the hex/b64 text (no trailing newline added by the plugin) and exits 0; with `-o` writes the bytes and prints "La operacion ha terminado correctamente " (exit 0).
- `createdigest DIR [-r] [-halgorithm A] [-hformat xml|txt] [-o OUT]`: prints or writes the XML/TXT document.
- `checkdigest FILE -i HASHFILE`: prints "Comprobacion de huella digital finalizada sin errores" when it matches or "Las huellas indicadas no se corresponden con las del archivo de entrada" when not — **both with exit code 0** (gotcha; a reimplementation may want a non-zero code for mismatch, but parity requires 0).
- `checkdigest DIR -i HASHFILE [-o REPORT]`: same messages based on `hasErrors`; with `-o` writes the `.hashreport` XML.
- Errors (missing/unreadable files: "No se ha especificado un fichero de entrada", "No se ha especificado un fichero de huellas", "No se encuentra el fichero o el directorio de entrada: %0", "No se tienen permisos de lectura sobre el fichero o el directorio de entrada: %0", "No se encuentra el fichero de huellas: %0", "No se tienen permisos de lectura sobre el fichero de huellas: %0", "Error en la lectura del documento de huellas", "No se ha podido cargar el documento de huellas", "El documento de huellas no es valido", "No se pudo generar el informe XML de huellas digitales", "Error al generar el documento de huella digital", "Error durante el calculo de huellas digitales", "No se ha podido escribir en el fichero de salida: %0") → message on stdout, exit `-1` (255). `IllegalArgumentException`s are printed prefixed by "Error no reconocido: ".

GUI mode (`-gui`):
- `createdigest PATH -gui [-o OUT] [-halgorithm A] [-hformat F] [-r]`: no dialog with options; directly computes (wait dialog) and opens the save dialog pre-filled with `OUT` (or default name). File: format from `-hformat` (default hex), clipboard copy **always on**. Directory: format default XML, final format decided by the saved extension (quirk: `-hformat hex` on a directory yields default name `<dir>.null`).
- `checkdigest [PATH] [-i HASHFILE] [-d] -gui`: if PATH missing, chooser for a file (title "Seleccionar fichero de datos", "Todos los ficheros (*.*)") or, with `-d`, a directory ("Seleccione el directorio de ficheros de los que comprobar la huella"); if `-i` missing/not a file, chooser for the hash file (title "Seleccione el fichero de huella digital" + filter "Documento de huella digital (*.hash, *.hashb64, *.hexhash)", or for directories "Seleccione el fichero de huellas digitales" + "Documento de huellas digitales (*.hashfiles, *.txthashfiles)"), initial dir = parent of PATH. Results shown as dialogs: file → "Las huellas digitales coinciden"/"Huellas coincidentes" or "Las huellas digitales no coinciden"/"Huellas no coincidentes" (error: "<html>Error comprobando la huella digital.<br>Asegúrese de que el fichero seleccionado es realmente un fichero de huella.</html>"); directory → as §7.5.6(d) then report save dialog.

Help text printed by `createdigest -help` (tabs as in original):
```
Sintaxis:
  Autofirma createdigest FICHERO [opciones...]		- Calcula la huella digital de un fichero
  Autofirma createdigest DIRECTORIO [opciones...]	- Calcula la huella digital de los ficheros de un directorio

Parametros:
  FICHERO		(Ruta del fichero del que calcular la huella digital)
  DIRECTORIO		(Ruta del directorio del que calcular las huellas digitales)

Opciones de fichero:
  -gui			 (Realiza la operacion con entorno grafico)
  -o FICHERO		 (Ruta del fichero de salida con la huella digital)
  -halgorithm ALGORITMO	 (Algoritmo de huella digital. Por defecto: SHA-256)
  -hformat FORMATO	 (Formato de salida cuando se indica por parametro el fichero)
  	 hex		 (Formato de la salida hexadecimal) (Por defecto)
  	 b64		 (Formato de la salida Base 64)
  	 bin		 (Formato de la salida binario. Solo valido con fichero de salida.)

Opciones de directorio:
  -gui			 (Realiza la operacion con entorno grafico)
  -o FICHERO		 (Ruta del fichero de salida con las huellas digitales)
  -halgorithm ALGORITMO	 (Algoritmo de huella digital. Por defecto: SHA-256)
  -hformat FORMATO	 (Formato de salida cuando se indica por parametro el fichero)
  	 xml		 (Formato de la salida XML) (Por defecto)
  	 txt		 (Formato de la salida texto plano)
  -r		 (Procesar los ficheros de los subdirectorios)
```
`checkdigest -help`:
```
Sintaxis:
  Autofirma checkdigest [FICHERO] [opciones...]		- Comprueba la huella digital de un fichero
  Autofirma checkdigest [DIRECTORIO] [opciones...]	- Comprueba las huellas digitales de los ficheros de un directorio

Parametros:
  FICHERO		(Ruta del fichero del que comprobar la huella digital)
  DIRECTORIO		(Ruta del directorio del que comprobar las huellas digitales)

Opciones de fichero:
  -gui			(Realiza la operacion con entorno grafico. Obligatorio si no se indica fichero/directorio)
  -i FICHERO		(Ruta del fichero de entrada con la huella digital)

Opciones de directorio:
  -gui			(Realiza la operacion con entorno grafico. Obligatorio si no se indica fichero/directorio)
  -i FICHERO		(Ruta del fichero de entrada con las huellas digitales)
  -o FICHERO		(Ruta del fichero de salida con el informe de validacion)
```

#### 7.5.11 Windows Explorer context menus (`HashPlugin.install/uninstall`)

Only on Windows (no-op on Linux/macOS). `install()`:
1. Working dir = AutoFirma install directory (directory of the JAR containing `AfirmaPlugin`) if writable, else `%ALLUSERSPROFILE%\Autofirma`; create sub-dir `hashplugin`.
2. Copy resource `registryInstallation/register.bat` (or `unregister.bat`) there, plus `execute.bat` with placeholders replaced: `$$PATH_BAT$$` → absolute path of the copied bat, `$$AUTOFIRMA_EXE$$` → `<install dir>\Autofirma.exe` (backslashes doubled).
3. Run `execute.bat`: it tests admin rights with `cacls.exe %SYSTEMROOT%\system32\config\system`; if not admin it re-launches itself through JScript `Shell.Application.ShellExecute("cmd.exe", "/c <bat> <exe>", "", "runas", 5)` (UAC prompt); if admin it runs `call "<bat>" "\"<exe>\""`.
4. Wait for the process, then sleep 5 s (because `waitFor` is unreliable with the elevated child), delete `hashplugin`.

`register.bat` (`%*` = quoted path to `Autofirma.exe`; every key is only added if `REG QUERY` fails, i.e. existing keys are not overwritten):

| Key (HKCR) | Value | Data |
|---|---|---|
| `*\shell\afirma.hashFile` | (default) | `Generar huella digital` |
| `*\shell\afirma.hashFile` | `Icon` | `"<...>\Autofirma.exe"` |
| `*\shell\afirma.hashFile\command` | (default) | `"<...>\Autofirma.exe" createdigest "%1" -gui` |
| `Directory\shell\afirma.hashDirectory` | (default) / `Icon` | `Generar huella digital` / exe |
| `Directory\shell\afirma.hashDirectory\command` | (default) | `"<exe>" createdigest "%1" -gui` |
| `.hash\shell\afirma.hash` | (default) / `Icon` | `Comprobar huella digital` / exe |
| `.hash\shell\afirma.hash\command` | (default) | `"<exe>" checkdigest -i "%1" -gui` |
| `.hashb64\shell\afirma.hashb64` (+`\command`) | same pattern | `"<exe>" checkdigest -i "%1" -gui` |
| `.hexhash\shell\afirma.hexhash` (+`\command`) | same pattern | `"<exe>" checkdigest -i "%1" -gui` |
| `.hashfiles\shell\afirma.hashfiles` (+`\command`) | same pattern | `"<exe>" checkdigest -i "%1" -d -gui` |

`unregister.bat`: `REG DELETE HKCR\*\shell\afirma.hashFile /f`, `HKCR\Directory\shell\afirma.hashDirectory`, `HKCR\.hash\shell\afirma.hash`, `HKCR\.hashb64\shell\afirma.hashb64`, `HKCR\.hexhash\shell\afirma.hexhash`, `HKCR\.hashfiles\shell\afirma.hashfiles` (all `/f`).

Notes / gotchas:
- `.txthashfiles` gets no context menu.
- Keys are written under the extension key itself (`HKCR\.hash\shell`), not under a ProgID; they disappear/collide if another app owns the extension.
- The AutoFirma uninstaller does **not** remove these keys (only removing the plugin does) → orphan menu entries after uninstall.
- `afirma-simple-plugin-hash-exe/HashPluginRegistryInstaller.vb` / `...Uninstaller.vb` are alternative .NET console tools (not wired into any build/installer) creating the same keys with `args(0) + "\AutoFirma.exe"` unquoted, a typo'd verb `.hashb64\shell\afirma.hasbh64`, and `.hashfiles` command **without** `-d`; the uninstaller also deletes the whole `.hash`, `.hashb64`, `.hashfiles`, `.hexhash` extension keys.
- `afirma-simple/src/main/resources/windows/afirma_register.bat` + `execute.bat` are the same elevation pattern used by "Restaurar instalación" to re-register the `afirma:` protocol (see §10), unrelated to hashes.

### 7.6 Certificate validation plugin — "Validación de certificados" (`afirma-simple-plugin-validatecerts`)

#### 7.6.1 Identity and UI
- Class `es.gob.afirma.plugin.certvalidation.ValidateCertsPlugin` (no hooks overridden). `plugin.json`: `name` = `validate_certs`, title "Validación de certificados", version 1.0 / code 1, authors ["Gobierno de España"], description "Plugin para la comprobación del estado de certificados de firma.<br><br>Este plugin permite validar los certificados utilizados para firmar con Autofirma. La validación se realiza mediante mecanismos predefinidos para los certificados de algunos prestadores de servicios de confianza y, en caso de no tener estos mecanismos predefinidos, contra la CRL o el OCSP declarado en el propio certificado.<br><br>Asegúrese de utilizar únicamente certificados emitidos por prestadores de confianza para firmar, ya que un certificado de un origen desconocido podría declarar mecanismos de validación no seguros."
- Permission: `BUTTONS` only. Two identical buttons, windows `single_result` and `multi_result`: title "Validar certificado de firma", icon `es/gob/afirma/plugin/certvalidation/certificate_16.png`, tooltip "Validar el certificado con el que se ha realizado la firma", accessible description "Valida el certificado utilizado para firmar", action `ValidateCertAction` (a `SignatureProcessAction`).
- It validates **only the certificate the user just signed with** (`signingCert`), not the certificates inside the signature.

Flow (`ValidateCertAction.processSignatures`):
1. `signingCert == null` → error dialog "No esá definido el certificado de firma" (typo in original), title "Error".
2. Modal wait dialog title "Validando certificado", label "Ejecutando proceso de validación...", indeterminate progress bar. Closing it cancels the work silently.
3. Background: choose verifier (§7.6.2). Failure or null → close wait dialog, error "No se dispone de ningún mecanismo de validación para el tipo de certificado utilizado".
4. Validate (§7.6.3) → dialog title "Estado de su certificado":

| `ValidationResult` | Dialog text | Icon |
|---|---|---|
| `VALID` | "El certificado es válido" | information |
| `EXPIRED` | "El certificado está caducado" | error |
| `REVOKED` | "El certificado está revocado" | error |
| `NOT_YET_VALID` | "El certificado aun no es válido" | error |
| `CA_NOT_SUPPORTED` | "Autoridad de certificación no soportada" | error |
| `CORRUPT` | "El certificado está corrupto" | error |
| `SERVER_ERROR` | "El servicio de validación devolvió un error" | error |
| `UNKNOWN` | "Se desconoce el estado del certificado." | error |
| `UNAUTHORIZED`, `MALFORMED_REQUEST`, `SIG_REQUIRED`, `CANNOT_DOWNLOAD_CRL` | "No se ha podido comprobar la validez del certificado" | error |

`ValidationResult` codes 0..11 = VALID, CORRUPT, CA_NOT_SUPPORTED, NOT_YET_VALID, EXPIRED, REVOKED, UNKNOWN, SERVER_ERROR, UNAUTHORIZED, MALFORMED_REQUEST, SIG_REQUIRED, CANNOT_DOWNLOAD_CRL; `toJsonString()` → `{"result":"OK"|"KO","reason":"<text from certvalidationmessages ValidationResult.N>"}` (unused by the UI).

#### 7.6.2 Verifier selection (`CertificateVerifierFactory`)
- Issuer identifier = `toHexString( CRC32(issuer DN DER encoding) + CRC32(ASCII bytes of the certificate's JCA signature algorithm name, e.g. "SHA256withRSA") )`, summed as 64-bit integers (may exceed 8 hex digits), lower-case, no leading zeros.
- Lookup in `validationfactory.properties`: `<id>.validation.type` (`ocsp`, `crl`, or a FQCN) and `<id>.validation.properties` (classpath resource with per-CA config). If `.properties` is missing the type is still used but the config becomes `default.validation.properties` (undefined → no config). Missing type → CRL verifier.

| Id | CA | Type | Config resource (issuerCertFile) |
|---|---|---|---|
| `133042780` | Camerfirma (CA general) | ocsp | `camerfirma/conf.properties.camerfirma` → `AC_CAMERFIRMA.cer` (CN=AC Camerfirma, exp. 2033) |
| `122ff5553` | Camerfirma RACER | ocsp | `camerfirma/conf.properties.camerfirma.racer` → `AC_RACER.cer` (CN=RACER, exp. 2023-12-04) |
| `188b56fd7` | Camerfirma Certificados Camerales | crl | `camerfirma/conf.properties.camerfirma.camerales` → `AC_CAMERFIRMA_CAMERALES.cer` (exp. 2034) |
| `feebeefc` | DNIe AC 001 SHA1 | ocsp | `dnie/conf.properties.dnie.001.sha1` → `ACDNIE001-SHA1.crt` |
| `14c508540` | DNIe AC 001 SHA2 | ocsp | `dnie/conf.properties.dnie.001.sha2` → `ACDNIE001-SHA2.crt` |
| `177f4be82` | DNIe AC 002 SHA1 | ocsp | `...dnie.002.sha1` → `ACDNIE002-SHA1.crt` |
| `1c55954c6` | DNIe AC 002 SHA2 | ocsp | `...dnie.002.sha2` → `ACDNIE002-SHA2.crt` |
| `128f5ce18` | DNIe AC 003 SHA1 | ocsp | `...dnie.003.sha1` → `ACDNIE003-SHA1.crt` |
| `1765a645c` | DNIe AC 003 SHA2 | ocsp | `...dnie.003.sha2` → `ACDNIE003-SHA2.crt` |
| `109af7fc9` | FNMT AC Componentes Informáticos | ocsp | `fnmt/componentes/conf.properties.fnmt.componentes.sha2` → `AC_Componentes_Informaticos_SHA256.cer` (OU=AC Componentes Informáticos, exp. 2028) |
| (`1298e89ae`, `df91d2fa`, `f9028f9e`) | FNMT Usuarios / Representación / Administración Pública | commented out | – |

All resources live under `/es/gob/afirma/plugin/certvalidation/validation/`. DNIe CA certs (C=ES, O=DIRECCION GENERAL DE LA POLICIA, OU=DNIE, CN=AC DNIE 00x) all expired 2021-02-26, so DNIe entries are obsolete. Config keys: `issuerCertFile` (classpath path of issuer CA cert), `signOcspRequest` (`false`), `responderUrl` (e.g. `http://ocsp.dnielectronico.es/`, `http://ocsp.camerfirma.com` (with trailing TAB), `http://ocspcomp.cert.fnmt.es/ocsp/OcspResponder`); for OCSP signing also `signStore`, `signStorePass`, `signAlias` (PKCS#12 on classpath; never configured). **Quirk:** `OcspCertificateVerifier.setSubjectCert` (called after the config is loaded) overwrites `responderUrl` with the URL taken from the certificate's AIA and forces `signOcspRequest=false`, so only `issuerCertFile` is effective.

#### 7.6.3 Validation algorithm (`CertificateVerifier.validateCertificate`)
1. now > notAfter → `EXPIRED`; now < notBefore → `NOT_YET_VALID`.
2. If an issuer cert is configured: issuer DN string of the cert must equal the configured CA's subject DN string, and the cert signature must verify with the CA public key; mismatch/bad signature → `CA_NOT_SUPPORTED`; other errors → `SERVER_ERROR`.
3. Revocation:
   - **OCSP**: responder = from the certificate's Authority Information Access extension, taking **all** URI access locations (OCSP and caIssuers alike): the first one, or if several, the **last** one whose URL contains "ocsp" (case-insensitive). No AIA → verifier creation fails ("No se dispone de ningún mecanismo..."). Request: unsigned `OCSPRequest` with a single `CertID` (SHA-1 over issuer name/key of the configured issuer cert — or of the cert itself if none), no nonce. HTTP POST, headers `Content-Type: application/ocsp-request`, `Accept: application/ocsp-response`, uses JVM proxy settings (§1/§4). Non-2xx → `SERVER_ERROR`. Response: status `successful` → first `SingleResponse`: good → `VALID`, revoked → `REVOKED`, unknown → `UNKNOWN`; `unauthorized` → `UNAUTHORIZED`; `internalError`/`tryLater` → `SERVER_ERROR`; `malformedRequest` → `MALFORMED_REQUEST`; `sigRequired` → `SIG_REQUIRED`. **The response signature, responder certificate, CertID match and thisUpdate/nextUpdate are not checked** (security gotcha).
   - **CRL**: distribution points = URI general names in `fullName` of the CRL Distribution Points extension. None → `UNKNOWN`. For each URL: download (`http://`, `https://`, `ftp://` via HTTP downloader; `ldap://` via LDAP attribute `certificateRevocationList;binary` of the base DN; `file:/` local), on download failure try next; parse (failure → `SERVER_ERROR`); if issuer key known, verify CRL signature (failure → `SERVER_ERROR`); serial listed → `REVOKED`. After the loop: at least one CRL checked → `VALID`; else any download failed → `CANNOT_DOWNLOAD_CRL`; else `UNKNOWN`. No CRL freshness (nextUpdate) or delta-CRL checks.
- Messages bundle: `es/gob/afirma/plugin/certvalidation/messages.properties` and `certvalidationmessages.properties` (Spanish only).

### 7.7 What is *not* part of the plugin system
- The protocol's own batch signing, the massive-signing engine (§6) and the CLI built-in commands do not consult plugins except as described (CLI command fallback, inline processors).
- There is no plugin download/update channel, no catalog and no signature trust list; plugins are installed only from local files.

### 7.8 Mapping to built-in features (recommendation for the Rust version)

- **Drop dynamic third-party plugins.** Java JARs cannot be loaded; do not ship the "Gestionar plugins" dialog unless an alternative extension format is designed. Keep the **hook points as internal traits/modules** so features can be composed: (1) per-file pre-sign data transform, (2) per-signature post-sign transform, (3) end-of-run reset, (4) screen action buttons for the input screen / single result / multi result / viewer with the same data contracts (§7.2.2), (5) main-menu entries, (6) CLI sub-commands, (7) protocol request processor (native = §7.2.5 format). None of (1)–(3) or (7) has an official consumer, so they can stay as no-op seams.
- **Migration**: on first run, if the legacy plugins directory (§7.3.1) contains an `installed` file listing `hash` and/or `validate_certs`, enable the corresponding built-in features (or simply always enable them); warn (log) about any other listed plugin that is no longer supported. Optionally import the hash preferences from the Java prefs node `/es/gob/afirma/plugin/hash` (Windows value names are Java-escaped, e.g. `create/Hash/Algorithm`). Leave the old directory untouched or clean it up behind a confirmation.
- **Digests (hash plugin) → built-in "Huellas digitales" menu + CLI**:
  - Implement the four dialogs (§7.5.6) as native windows with the same defaults and preference keys (store them in the app's own preference store, §4, e.g. under a `hash.` prefix, keeping the documented names).
  - Keep **byte-exact file formats**: `.hexhash` (UPPER hex + `h`), `.hashb64` (standard Base64), `.hash` (raw), `.hashfiles` XML (URL-safe Base64 `hash` + `hexhash`), `.txthashfiles` (CRLF, `;` headers, hex without `h`), `.hashreport` XML. Be liberal when reading (accept lower-case hex, missing `h`, trailing whitespace/newline, both path separators, missing `hexhash`), strict and deterministic when writing (sort entries; prefer `/` separators — note this is a deliberate deviation if chosen).
  - Keep CLI commands `createdigest` / `checkdigest` with identical options, texts and exit codes (0 even on mismatch, documented as a parity decision; consider an opt-in flag for non-zero mismatch exit).
  - Use a bounded thread pool (≈10 workers) and a progress dialog; report per-file read errors instead of silently truncating.
  - **Context menus as installer-time integration** (not runtime UAC elevation): Windows — register under `HKCU\Software\Classes` (per-user) or `HKLM\Software\Classes` (per-machine installer) the verbs `afirma.hashFile` (`*`), `afirma.hashDirectory` (`Directory`), and "Comprobar huella digital" for `.hash`, `.hashb64`, `.hexhash`, `.hashfiles` (with `-d`) — and also `.txthashfiles` (fix) — removing them on uninstall; preferably via a ProgID (`Autofirma.HashFile`) instead of writing under the extension key. Linux — `.desktop` actions / file-manager integrations (Nautilus scripts or extension, Dolphin service menu `ServiceMenus/*.desktop`, Nemo actions) invoking `autofirma createdigest %f -gui`; register MIME types for the hash extensions if "open with" verification is wanted. macOS — Finder Quick Actions / Services (or a Finder Sync extension) calling the same CLI. See §9 for the installer.
- **Certificate validation → built-in "Validar certificado de firma" button** on the single-result and multi-result screens (and optionally also in the viewer for each signer certificate):
  - Validate the signing certificate: validity period → OCSP from AIA (only `id-ad-ocsp` access methods, not caIssuers) → fallback CRL from CRLDP (HTTP/HTTPS/LDAP/file); honour the app proxy settings.
  - Do it properly: build the chain (from the keystore's chain or AIA caIssuers), verify the OCSP response signature/responder authorization, CertID, `thisUpdate`/`nextUpdate`, add a nonce optionally; verify CRL signature and freshness. Keep the same result enum and Spanish messages for parity.
  - The CRC-based per-CA table can be dropped (it only pins issuer certs, mostly expired); if kept, replicate the id formula exactly.
- **Inline processors**: implement only the native response format in the protocol layer (owned by the protocol spec).
- **Security improvements to record as intentional deviations**: no world-writable shared plugin directory; no executing code from user-supplied files; no UAC-elevated batch scripts at runtime.


## 8. Updater (optional)

The original "updater" is only a **new-version notifier**: it never downloads or installs anything. It compares an integer build number published on a government web server with the build number compiled into the application and, if newer, offers to open the download page in the browser. Classes: `es.gob.afirma.standalone.updater.Updater`, `UpdaterMessages`; resources `properties/updater.properties`, `properties/updatermessages/updatermessages_<ll_CC>.properties`.

### 8.1 Version metadata (`/properties/updater.properties`, bundled in the JAR)

| Key | Value (v1.10) | Meaning |
|---|---|---|
| `currentVersionText.WINDOWS` / `.LINUX` / `.MACOSX` | `1.10` | Human-readable version (window title `Autofirma v1.10`, About dialog, `help.version` file). Unknown OS → `"0"`. |
| `currentVersion.WINDOWS` / `.LINUX` / `.MACOSX` | `21` | Internal integer build number. Comment in the file: even numbers are preliminary (pre-release) builds and the number does not advance across pre-releases; odd numbers identify final releases. Unknown OS → `"0"`. |
| `urlWindows` | `http://estaticos.redsara.es/comunes/autofirma/autofirmawindows.version` | Version file for Windows |
| `urlLinux` | `http://estaticos.redsara.es/comunes/autofirma/autofirmalinux.version` | Version file for Linux |
| `urlMacosx` | `http://estaticos.redsara.es/comunes/autofirma/autofirmamacosx.version` | Version file for macOS |
| `url` | `http://estaticos.redsara.es/comunes/autofirma/autofirma.version` | Generic URL – **unused** by the code |
| `updateSite` | `http://firmaelectronica.gob.es/Home/Descargas.html` | Page opened when the user accepts the update |

The OS suffix is the `Platform.OS` enum name (`WINDOWS`, `LINUX`, `MACOSX`); other OSes get no URL and the check is skipped with a warning.

### 8.2 Remote version file format

Plain text body containing a single integer build number (e.g. `21`), optionally surrounded by whitespace/newlines (the body is decoded with the platform charset and `trim()`ed). Comparison: `Integer.parseInt(remote) > Integer.parseInt(currentVersion.<OS>)` → update available. Any parse error / HTTP error → treated as "cannot check" (silently logged).

### 8.3 When the check runs and what gates it

Called once from `SimpleAfirma.main` (step 11 in §1.3), i.e. in **desktop GUI mode and in afirma:// protocol mode** (not in CLI mode). Gates, all must pass:

1. `SimpleAfirma.updatesEnabled` static flag (default `true`; set to `false` programmatically by the Java Web Start variant `AutoFirmaProtocolWebStart`).
2. JVM system property `es.gob.afirma.doNotCheckUpdates` is not `true` **and** environment variable `AUTOFIRMA_AVOID_UPDATE_CHECK` is not `true` (case-insensitive `Boolean.parseBoolean`). If either disables updates, `updatesEnabled` becomes false for the whole run and the Preferences "check for updates" checkbox is shown unchecked and disabled (§4).
3. Preference `checkForUpdates` (boolean, default `true`, General tab, label `PreferencesPanel.87`; can be locked/forced by administrators, §4). It is checked both in `main` and again inside `checkForUpdates()`.
4. At most once per calendar day: the date of the last **successful** check is stored with `java.util.prefs` in the user node `es/gob/afirma/standalone`, key `lastCheckDate`, format `yyyyMMdd` (Windows registry: `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\standalone`, value name escaped by Java as `last/Check/Date`; Linux: `~/.java/.userPrefs/es/gob/afirma/standalone/prefs.xml`; macOS: Java's plist-backed user preferences). The check is skipped if `(lastCheck.dayOfYear >= today.dayOfYear && lastCheck.year == today.year) || lastCheck.year > today.year`. Missing/unparseable date → treated as year 2000 (check runs).

### 8.4 Procedure

1. Spawn a background thread (the GUI/protocol flow continues immediately).
2. `join()` the `SSLContextConfigurationTask` (§1.14) so that proxy and trust settings are in place.
3. GET the per-OS URL through `HttpManager` (honours proxy, `secureConnections`, `secureDomainsList`; untrusted-certificate import dialog may appear for HTTPS).
4. On failure (network, parse, missing current version): log at INFO and stop; `lastCheckDate` is **not** updated (so it will retry next launch).
5. On success: store today as `lastCheckDate` and flush preferences.
6. If a newer build exists: modal confirm dialog (parent = none, YES/NO, information icon):
   - Title `Updater.2`: "Actualización disponible" (en: "Update available").
   - Message `Updater.1`: `<html>Hay disponible una nueva versión del aplicativo.<br>¿Desea ir al sitio de actualización?</html>` (en: "A new version of the app is available. Do you want to go to the upgrade site?").
   - YES → open `updateSite` in the default browser; if that fails, error dialog `Updater.3` "No se ha podido abrir el sitio Web de actualizaciones de Autofirma", title `Updater.4` "Error".
7. Otherwise log "latest version installed".

`Updater.5` ("La operación no puede completarse porque la versión instalada de "Autofirma" está obsoleta…") and `Updater.isOldVersion(String)` exist but are not used; the web-requested minimum version (`mcv` URL parameter, error `500005`) is handled by the protocol layer.

### 8.5 Other uses of the version data

- `Updater.getCurrentVersionText()` → window title, About dialog, `help.version` (§1.15).
- `Updater.getCurrentVersion()` → `HelpResourceManager.isDifferentHelpFile()` (compares against the build number; unused path).

### 8.6 Reimplementation notes

- Treat as optional/feature-flagged; keep the same three opt-outs (env var, JVM-prop equivalent env/CLI flag, preference + admin lock) because corporate deployments rely on them.
- Keep the remote format (single integer) and URLs configurable at build time; use HTTPS if the server supports it (the original uses plain HTTP — a MITM could at most trigger the dialog that opens a fixed URL, since the opened URL is not taken from the response).
- Do not show the dialog in protocol (web-invoked) mode, or at least do not block the signing flow (the original shows it with no parent, potentially on top of the web-triggered dialogs).
- Linux distributions and store builds (MSIX, Mac App Store) should disable it at build time.


## 9. Installer and configurator per OS

This section describes what the original installers and the *installation-time configurator* (`afirma-ui-simple-configurator`, aka "AutofirmaConfigurador") do on each OS. That covers the files they install, how they integrate with the desktop (protocol handler, file associations, context menu), how they generate the local TLS certificate and get it trusted by the OS and browsers, and how they uninstall. The "Restore configuration" menu feature of the running app repeats a large part of this at runtime and is covered in §10. Preference keys written through `-config_path` belong to §4.

> Scope note: the afirma:// URL format, the WebSocket ports and the TLS handshake used by the browser are covered by the protocol spec. Here we only cover **producing and trusting** the certificate the app serves on `127.0.0.1` and **registering** the `afirma:` scheme.

### 9.1 Overview and architecture

| Piece | Java/other artefact | Role |
|---|---|---|
| Configurator (graphical/console) | `AutofirmaConfigurator` (main class of `autofirmaConfigurador.jar`) | Used on **Linux** (deb/rpm post-install) and **macOS** (pkg `postinstall`). Generates the CA and SSL certificates. Installs or prepares installation of the CA in OS/browser stores, applies the language and config-file options, and uninstalls (`-uninstall`). |
| Configurator (silent) | `AutofirmaConfiguratorSilent` (main class of the Windows wrapper `AutofirmaConfigurador.exe`, see launch4j §9.3.6) | Same work on **Windows**. Has no visible console window, but error, retry and password dialogs can still appear. |
| OS strategy | `Configurator` interface: `configure(Console)`, `uninstall(Console, PluginsManager)`, `getAplicationDirectory()`, `getAlternativeApplicationDirectory()` | Implementations: `ConfiguratorWindows`, `ConfiguratorLinux`, `ConfiguratorMacOSX`. Any other OS logs a warning and does nothing. |
| Firefox/NSS helpers | `ConfiguratorFirefoxWindows`, `ConfiguratorFirefoxLinux`, `ConfiguratorFirefoxMac` | Locate Firefox profiles and run NSS `certutil`. They also write `user.js` (`security.enterprise_roots.enabled`). |
| Certificate generation | `CertUtil` (configurator), uses BouncyCastle | Produces the local CA and the localhost SSL certificate (see §9.2). |
| Output | `Console` with `IoConsole` (`System.console().printf`), `PrintConsole` (`System.out.println`), `GraphicConfiguratorConsole` (Swing JFrame) | `ConsoleManager.getConsole(listener)` returns the graphical console only when the JVM is not headless, the OS is **not Linux**, and a listener is supplied. Otherwise it returns `IoConsole` when a terminal is attached, else `PrintConsole`. **On Linux the configurator never shows a GUI console.** |
| Shared code | `afirma-ui-simple-configurator-common`: `ConfiguratorUtil`, `ConfigUpdaterManager`, `ConfigDataInfo`, `PreferencesManager`, `PreferencesPlistHandler`, `XAdESValidator` | File install, unzip (with zip-slip protection), script helpers, constant `CERT_ALIAS = "SocketAutoFirma"`, and the config-file import (`-config_path`). |
| Windows installers | `Autofirma_NSIS_project_EXE_{32,64}.nsi` (interactive EXE), `Autofirma_NSIS_project_MSI_{32,64}.nsi` (builds `AutofirmaGenerator.exe`, which the MSI wraps), `Autofirma_{32,64}_installer.wxs` (WiX MSI) | §9.3 |
| Linux packages | `linux/instalador_deb/**` (Debian/Ubuntu), `linux/instalador_rpm_fedora/**`, `linux/instalador_rpm_suse/**` | §9.4 |
| macOS package | `macos/Autofirma_Packages_{aarch64,x64,for_old_systems}/Autofirma.pkgproj` (the *Packages* app by WhiteBox), `scripts/postinstall`, launcher app `macos/Lanzador/**` | §9.5 |

**Gotcha (Windows):** the installer itself (NSIS, Win32 crypt32 API) adds the CA to the Windows trust store, **not** the configurator. The configurator only does that for the legacy JNLP deployment.

#### 9.1.1 Configurator command line (both main classes)

Arguments are matched case-insensitively (`equalsIgnoreCase`). Options that take a value consume the next argv element. Unknown arguments are ignored; the Windows installers pass an unused `/passive`. Every argument is logged at WARNING level (`"ARGUMENTO normal: …"` / `"ARGUMENTO SILENT: …"`).

| Option | Value | `AutofirmaConfigurator` | `AutofirmaConfiguratorSilent` | Effect |
|---|---|---|---|---|
| `-install` | – | ✓ (default operation) | ✓ (default) | Run `configure()`. |
| `-uninstall` | – | ✓ | ✓ | Run `uninstall()` (see per-OS sections), then `PreferencesManager.removeSystemPrefs()` and `KeyStorePreferencesManager.removeSystemPrefs()` (remove system-level preference nodes, §4). |
| `-keep_open` | – | ✓ | ✗ | Do not call `System.exit` at the end (`closeApplication(code, keepOpen)` only disposes the console). |
| `-headless` | – | ✓ | ✗ (implicitly true on macOS) | No graphical console. On macOS it also means "do not ask the Firefox question; use `-firefox_roots` as given". |
| `-jnlp` | – | ✓ | ✗ (always false) | Legacy Java Web Start deployment. Generated files go to a user-writable directory (Windows `%ALLUSERSPROFILE%\Autofirma`, Linux `~/.afirma/Autofirma`). On Windows the CA is also imported into the user ROOT store (§9.3.4). |
| `-firefox_roots` | – | ✓ (Windows, macOS) | ✓ | Write `user_pref("security.enterprise_roots.enabled", true);` to every Firefox profile's `user.js` (Windows and macOS only). |
| `-certificate_path` | path | ✓ (Windows only) | ✓ (Windows only) | Administrator-supplied CA certificate. It is used only if `-keystore_path` is also given; it is copied to `<appDir>\Autofirma_ROOT.cer`. |
| `-keystore_path` | path | ✓ (Windows only) | ✓ (Windows only) | Administrator-supplied SSL PKCS#12. It is copied to `<appDir>\autofirma.pfx` and must open with password `654321` (see §9.2). |
| `-config_path` | local path or `https:` URL | ✓ | ✓ | After install/uninstall, import a system preference file (XML plist; format in §4) via `ConfigUpdaterManager.savePrefsConfigFile(path, updateConfig)`. **Silent only:** if the value starts with `https:`, every `\` is replaced by `/`, because MSI property passing mangles forward slashes, so admins write `https:\\host\file`. |
| `-update_config` | – | ✓ | ✓ | Store `allowUpdateConfig=true`, but only if the config path is `https://`. The app then re-downloads the file at most once per day (§9.6). |
| `-language_path` | path to language pack ZIP | ✓ | ✓ | `LanguageManager.addLanguage(file)`. The ZIP must contain `metadata.info` (`locale=xx_YY`, `language.name=…`). It is extracted to `<languagesDir>/<xx_YY>/` (§11). |
| `-default_language` | `xx_YY` (e.g. `es_ES`, `ca_ES`, `gl_ES`, `eu_ES`, `va_ES`, `en_US`, or an imported locale) | ✓ | ✓ | If the locale is built in or was imported: `Locale.setDefault`, reload messages, write the **system** preference `default.locale` (`PreferencesManager.PREFERENCES_LOCALE`) and flush it. Otherwise log a warning. Malformed values without `_` throw, and the error is logged. |

`languagesDir` (`DirectoryUtil.getLanguagesDir()`) is always `<alternativeDir>/languages`. The alternative directory is `%ALLUSERSPROFILE%\Autofirma` on Windows, `~/.afirma/Autofirma` on Linux and `$HOME/Library/Application Support/Autofirma` on macOS.

**Execution order (`main`):** parse args → `LanguageManager.init(languagesDir)` → `-language_path` → `-default_language` (+ `flushSystemPrefs`) → (macOS GUI variant: set the Dock icon to `/logo_cliente_256.png`) → `uninstall()` or `configure()` → if `-config_path` is set, import the config → `closeApplication(0)`.

**Exit codes:**
- `0`: normal end, including uninstall, which never fails.
- `-1` (POSIX status 255): `configure()` threw any `Exception` or `Error`. The process exits **before** the `-config_path` import, so the config is not applied. In the GUI variant a `-keep_open` run does not exit, only disposes the console.
- **Silent variant:**
  - A `HeadlessException` shows error text `AutofirmaConfigurator.7` and continues, ending with exit code 0.
  - Any other exception shows `AutofirmaConfigurator.0` (`"Ocurrió un error durante la configuración de Autofirma.\nAutofirma no podrá comunicarse con su navegador web."`) and exits -1.
- Error text printed to the console before rethrowing:
  - `AutofirmaConfigurator.3` (`"Error al copiar o leer alguno de los ficheros de configuración"`): `IOException`.
  - `AutofirmaConfigurator.4` (`"Error al generar las claves de cifrado SSL"`): `ConfigurationException`.
  - `AutofirmaConfigurator.5`: `GeneralSecurityException`.

**Configurator log file:** java.util.logging `FileHandler`, XML format, 2 MiB limit, 1 file, no append. File name `AUTOFIRMA_CONFIGURATOR.afirma.log.xml`, in:
- Windows: `%HOMEDRIVE%%HOMEPATH%\.afirma\`. The real user's profile is used because the process runs elevated; if that directory does not exist, `~/.afirma/`.
- Linux: `/var/tmp/` if writable, else `/var/temp/`, else `java.io.tmpdir`.
- macOS: `$HOME/Library/Application Support/Autofirma/` (created and chmod 0777 in the GUI variant), else `/var/tmp`, `/var/temp`, `java.io.tmpdir`.

**Graphical console** (`GraphicConfiguratorConsole`): a JFrame titled `"Configurador"` (`ConfiguratorConsole.0`), 480×350, centred. It holds a read-only `JTextArea` in a scroll pane with 11 px insets and uses the icon `/logo_cliente_256.png`. The close button calls the listener, which exits with code 0. Each `print()` appends the text plus `\n` and logs `"Mensaje de consola: …"`. Colours come from the configurator's own `LookAndFeelManager`:
- high contrast if the Windows desktop property `win.highContrast.on` is set; on Linux high contrast is always assumed;
- "large font" if `win.defaultGUI.font.height > 12`; on Linux always assumed;
- Nimbus look and feel unless high contrast or large font applies;
- macOS gets `apple.laf.useScreenMenuBar` and related properties.

### 9.2 Local TLS certificate (all OSes)

`CertUtil.getCertPackForLocalhostSsl(alias="SocketAutoFirma", password="654321")` produces a **new CA and a new SSL certificate on every run**. There is no reuse except the "already generated" check described per OS.

| Item | CA ("root") certificate | SSL (leaf) certificate |
|---|---|---|
| Key | RSA 2048 (`KeyPairGenerator "RSA"`, `SecureRandom`) | RSA 2048 (separate key) |
| Signature algorithm | `SHA256withRSA` (self-signed), BouncyCastle provider `SC` | `SHA256withRSA`, signed by the CA key |
| Subject DN | `CN=Autofirma ROOT` (`CertUtil.ROOT_CERTIFICATE_PRINCIPAL`) | `CN=127.0.0.1` |
| Issuer DN | `CN=Autofirma ROOT` | `CN=Autofirma ROOT` (the CA's subject) |
| Serial | `BigInteger.valueOf(new java.util.Random().nextInt())`, a signed 32-bit value. **Gotcha:** it can be negative or zero, which violates RFC 5280; use a positive random serial of at least 64 bits. | same rule |
| Validity | notBefore = now (no backdating, so clock skew is a risk); notAfter = now + 10×365 days (3650 days, leap days ignored) | same |
| Subject Key Identifier | non-critical; SHA-1 of the subjectPublicKey (RFC 5280 method 1) | non-critical; same method |
| Authority Key Identifier | – | non-critical; keyIdentifier = SHA-1 of the CA public key |
| BasicConstraints | **critical**, `CA:true`, no pathLen | non-critical, `CA:false` |
| KeyUsage | non-critical: `keyCertSign, digitalSignature, keyEncipherment, dataEncipherment, cRLSign` | **none** |
| ExtendedKeyUsage | non-critical: `serverAuth, clientAuth, anyExtendedKeyUsage` | **none** |
| SubjectAltName | – | non-critical: `iPAddress 127.0.0.1`, `dNSName "127.0.0.1"` (sic), `dNSName "localhost"`. **No `::1`.** |

**Files** (all DER, no PEM):

| File | Content | Written on |
|---|---|---|
| `autofirma.pfx` | PKCS#12 (`KeyStore "PKCS12"`, JDK default PBE/MAC algorithms). One key entry, alias **`SocketAutoFirma`**, key password = store password = **`654321`**, chain `[SSL cert, CA cert]` | all OSes |
| `Autofirma_ROOT.cer` | CA certificate, DER | all OSes |
| `autofirma.cer` | SSL leaf certificate, DER | macOS only (it is trusted directly in the keychain) |

The running app (`SecureSocketUtils`) looks for `autofirma.pfx` in `DesktopUtil.getApplicationDirectory()` (the directory of the running jar/exe) and then in the alternative directory. It opens the file with password `654321` and alias-agnostic key selection (default JSSE KeyManager). An administrator-supplied keystore (Windows `-keystore_path`) must therefore be a PKCS#12 with store and key password `654321` and any alias.

**Where the files live:**

| OS | Directory written by the configurator | Runtime lookup order |
|---|---|---|
| Windows | `<appDir>` = directory of `AutofirmaConfigurador.exe` = `<INSTDIR>\Autofirma\` (default `C:\Program Files\Autofirma\Autofirma\`). JNLP: `%ALLUSERSPROFILE%\Autofirma` | app dir, then `%ALLUSERSPROFILE%\Autofirma` (the latter is used by "Restore configuration", §10) |
| Linux | `<appDir>` = directory of `autofirmaConfigurador.jar` = `/usr/lib/Autofirma` (deb) or `%{_libdir}/autofirma` (rpm, e.g. `/usr/lib64/autofirma`). JNLP: `~/.afirma/Autofirma` | app dir, then `~/.afirma/Autofirma` |
| macOS | always `$HOME/Library/Application Support/Autofirma` (`getResourcesDirectory(true)`, created with 0777 permissions) | app dir (`…/Autofirma.app/Contents/Resources/JAR`, normally has no pfx), then `$HOME/Library/Application Support/Autofirma` |

**NSS (Firefox/Chrome-on-Linux) usage:**
- The CA is imported with nickname `SocketAutoFirma` (`ConfiguratorUtil.CERT_ALIAS`).
- Trust flags are `-t "C,,"` (trusted CA for SSL) for Firefox profiles, and `-t "TCP,TCP,TCP"` for the Linux `~/.pki/nssdb` stores used by Chrome/Chromium.
- When deleting, the Windows code also tries the legacy nickname `"Autofirma ROOT"`.

**Gotchas for the reimplementation:**
- The leaf has no EKU `serverAuth` and is valid for 10 years. Apple platforms reject such a certificate if it is trusted only through the CA (825-day / EKU rules). That is why macOS also trusts the leaf itself with `trustAsRoot` (§9.5.3). A reimplementation should add `EKU serverAuth` and `KeyUsage digitalSignature,keyEncipherment` to the leaf, consider an `iPAddress ::1` SAN, and use a validity that macOS accepts if only the CA is trusted.
- The password `654321` and the file names are effectively a contract with administrator tooling (MSI `CERTIFICATE_PATH`/`KEYSTORE_PATH`) and with "Restore configuration" (§10). Keep them if compatibility with existing installs is required.
- `trust_settings.plist` (`afirma-simple/src/main/resources/osx/trust_settings.plist`) is an **unused legacy template**: grep finds no Java reference. It is a macOS `trustList` with placeholders `%SSL_SHA1%`, `%SSL_SERIALNUMBER%`, `%CA_SHA1%`, `%CA_SERIALNUMBER%`, and `issuerName` = DER of `CN=AutoFirma ROOT` (old capitalisation, base64 `MBkxFzAVBgNVBAMMDkF1dG9GaXJtYSBST09U`). For the SSL entry every policy has `kSecTrustSettingsResult = 2` (TrustAsRoot). For the CA entry every policy has result `1` (TrustRoot), plus one policy-less entry. The policies covered are sslServer (OID `1.2.840.113635.100.1.3`, two entries with allowed errors `-2147409654` and `-2147408896`), SMIME (`…1.8`, allowed errors `-2147409654` and `-2147408872`), eapServer (`…1.9`), ipsecServer (`…1.11`), CodeSigning (`…1.16`), AppleTimeStamping (`…1.20`) and basicX509 (`…1.2`). The `modDate` values are from 2017-02-27. Effectively this means "trust for everything", which `security add-trusted-cert -r trustRoot|trustAsRoot` (without `-p`) already achieves.

### 9.3 Windows

#### 9.3.1 Installer variants

| Variant | Script | Output | UI |
|---|---|---|---|
| Interactive EXE 64-bit | `Autofirma_NSIS_project_EXE_64.nsi` | `Autofirma64/Autofirma_64_v1_10_installer.exe` | NSIS Modern UI |
| Interactive EXE 32-bit | `Autofirma_NSIS_project_EXE_32.nsi` | `Autofirma32/Autofirma_32_v1_10_installer.exe` | same |
| MSI payload (64/32) | `Autofirma_NSIS_project_MSI_{64,32}.nsi` | `Autofirma{64,32}\AutofirmaGenerator.exe` (silent NSIS, driven by parameters) | none |
| MSI wrapper | `Autofirma_{64,32}_installer.wxs` + `Autofirma_to_msi_{64,32}.bat` (`candle`, then `light -ext WixUtilExtension`; renamed to `Autofirma_{64,32}_v1_10_installer.msi`) | `.msi` | standard MSI |

Version constants: `VERSION "1.10"`, `FILE_VERSION "1.10.0.0"`. VersionInfo: ProductName `Autofirma`, LegalCopyright `(C) Gobierno de España`, FileDescription `Autofirma (64 bits)` / `(32 bits)`. The build signs the outputs with `signtool sign /f Autofirma_sign.pfx /p <pwd> <file>` (`Autofirma_sign_*.bat`). Compression is `SetCompressor lzma`, with `CRCCheck on`. The installer icon is `ic_launcher.ico`; header and wizard bitmaps are `ic_head.bmp` and `ic_install.bmp`.

NSIS plugins and includes used:
- `MUI.nsh`, `Sections.nsh`, `nsDialogs.nsh`, `LogicLib`;
- `nsProcess` (find or kill `firefox.exe`);
- `Registry` (`registry::Open/Find`, used to search for old installs);
- `NTProfiles.nsh`: included but **never used**;
- MSI payload only: `FileFunc.nsh` (`GetParameters`/`GetOptions`).

Installer languages are Spanish (default), English, Catalan, Basque, Galician and Valencian (custom `NSIS/Contrib/Language Files/Valencian.nlf/.nsh`). The strings are in `NSIS/plugins/lang_strings.nsh`, and licences in `license\licencia_{es,en,ca,gl,eu,va}.txt`. Language IDs mapped to the Autofirma locale passed to the configurator: `3082→es_ES`, `1027→ca_ES`, `2051→va_ES`, `1110→gl_ES`, `1069→eu_ES`, `1033→en_US`; anything else → `es_ES`.

#### 9.3.2 Interactive EXE installer: pages and options

1. **`.onInit`:**
   - The language selection dialog (`MUI_LANGDLL_DISPLAY`, title `"Instalador de Autofirma"`, text `"Seleccione el idioma del instalador."`) defaults to Spanish.
   - The custom-page defaults are: Start-menu ✓, Desktop shortcut ✓, Firefox roots ✗.
   - `INSTALL_JRE = "true"`.
   - `isValidJavaVersionAvailable` runs `java -version` (from PATH) and parses the quoted version: `1.x` → x, otherwise the major number. The version must be ≥ 8, and on 64-bit `java -Xinternalversion` must contain `64-Bit`. If no valid Java is found, the "Java Runtime Environment" section is forced to *selected + read-only* (flags 17).
2. Pages, in order:
   1. Welcome.
   2. License (`MUI_PAGE_LICENSE $(LICENSE)`).
   3. Directory (`DirText "Elija un directorio donde instalar la aplicación:"`). Default `InstallDir "$PROGRAMFILES64\Autofirma"`; on 32-bit, `$PROGRAMFILES\Autofirma`.
   4. **Custom page "Opciones de integración avanzadas" / "Seleccione las opciones de integración que desee que configure Autofirma"** with three checkboxes:
      - `"Agregar al menú inicio."`
      - `"Crear acceso directo en el escritorio."`
      - `"Configurar Firefox para que confíe en los certificados raíz del sistema."`
   5. Components: "Autofirma" (read-only) and "Java Runtime Environment". Deselecting the JRE sets `INSTALL_JRE=false`.
   6. Install files.
   7. Finish.
3. Uninstaller pages: welcome, confirm, progress, finish.

Silent mode (`/S`, standard NSIS, plus `/D=<dir>`) skips the pages and uses the `.onInit` defaults.

#### 9.3.3 Interactive EXE installer: install section, step by step

`$PATH = "Autofirma"`, so the program directory is `$INSTDIR\Autofirma`.

1. **64-bit only:** `IsWow64Process`. If the OS is 32-bit, show `"No se puede instalar Autofirma 64 bits en un entorno 32 bits."` and quit.
2. **Previous version check (`CheckVersionInstalled`):**
   - Read `HKLM\SOFTWARE\Autofirma\Version` from the 64-bit view, then the 32-bit view. The 32-bit installer looks in the 64-bit view only on 64-bit Windows.
   - `VersionCheck(installed, new)` returns 0 if equal, 1 if the installed version is newer, 2 if the new one is newer:
     - 0 → `"Esta versión de Autofirma ya está instalada."` and quit.
     - 1 → `"La versión actual de Autofirma es más nueva que la que se quiere instalar."` and quit.
     - 2 → `RemoveOldVersions`.
3. **`RemoveOldVersions`:**
   1. Find the old install: first `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Autofirma\UninstallString` plus `DisplayVersion` (only if older). If that is missing, search the `Uninstall` subkeys for a value `DisplayName` equal to `AutoFirma` or `Autofirma`.
   2. Ask `UNINSTALL_OLDER` (`"La instalación de Autofirma requiere desinstalar la versión anterior … ¿Desea continuar?"`). In silent mode the answer is Yes; No quits.
   3. **Preserve user preferences:** if `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\standalone\ui\preferences` exists, copy its *values* to the first free `HKCU\Software\JavaSoft\Prefs\copia<N>`.
   4. If the uninstall string contains `msiexec`, run it with `/qn` from `$SYSDIR`. Otherwise run `"<UninstallString>" /S _?=<oldDir>`.
   5. If the old directory differs from `$INSTDIR`, delete it with `RMDir /r`, but only when it contains `Program Files (x86)\` or `Program Files\` or `Autofirma`.
   6. Copy the backed-up values back and delete `copia<N>`.
4. `SetRegView 64` (32 for the 32-bit installer). Delete `$INSTDIR\Autofirma`, looping until it is gone with a 3 s sleep.
5. **Files copied** to `$INSTDIR\Autofirma\`:
   - `Autofirma.exe` (GUI launcher), `AutofirmaConfigurador.exe` (configurator), `AutofirmaCommandLine.exe` (console launcher);
   - `licencia_{es,en,ca,va,eu,gl}.txt`;
   - `ic_firmar.ico` (signature document icon);
   - if `INSTALL_JRE == "true"`, the bundled JRE tree to `$INSTDIR\Autofirma\jre\` (`java64\jre` or `java32\jre`).
6. `SetShellVarContext all`, so shortcuts are created for all users.
7. **Firefox must be closed:** loop on `nsProcess::FindProcess "firefox.exe"` showing `"Cierre el navegador Mozilla Firefox para continuar con la instalación de Autofirma."` (OK only). **Gotcha:** this MessageBox has no `/SD`, so in silent mode it loops until Firefox exits. Then sleep 2 s.
8. **Shortcuts:**
   - Desktop: `$DESKTOP\Autofirma.lnk` → `$INSTDIR\Autofirma\Autofirma.exe`.
   - Start menu: `$SMPROGRAMS\Autofirma\Autofirma.lnk` and `$SMPROGRAMS\Autofirma\Desinstalar.lnk` → `$INSTDIR\uninstall.exe`.
9. **Registry, Add/Remove Programs:** key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Autofirma`:

   | Value | Type | Data |
   |---|---|---|
   | `DisplayName` | REG_SZ | `Autofirma` |
   | `UninstallString` | REG_SZ | `$INSTDIR\uninstall.exe` |
   | `DisplayIcon` | REG_SZ | `$INSTDIR\Autofirma\Autofirma.exe` |
   | `NoModify` | DWORD | 1 |
   | `NoRepair` | DWORD | 1 |
   | `EstimatedSize` | DWORD | 100000 |
   | `Publisher` | REG_SZ | `Gobierno de España` |
   | `DisplayVersion` | REG_SZ | `1.10` |

   `WriteUninstaller "$INSTDIR\uninstall.exe"`.
10. **Registry, app key:** `HKLM\SOFTWARE\Autofirma`, with `InstallDir` = `$INSTDIR` and `Version` = `1.10`.
11. **Registry, shell integration (HKCR):**

    | Key | Value | Data |
    |---|---|---|
    | `HKCR\*\shell\afirma.sign` | (Default) | localized `SIGN_WITH_AUTOFIRMA`, e.g. **`Firmar con Autofirma`** |
    | `HKCR\*\shell\afirma.sign` | `Icon` | `$INSTDIR\Autofirma\Autofirma.exe` |
    | `HKCR\*\shell\afirma.sign\command` | (Default) | `$INSTDIR\Autofirma\Autofirma.exe sign -gui -i "%1"` |
    | `HKCR\.csig` | (Default) | localized `BINARY_SIGNATURE` (`Firma binaria CMS/CAdES`) |
    | `HKCR\.csig\DefaultIcon` | (Default) | `$INSTDIR\Autofirma\ic_firmar.ico` |
    | `HKCR\.csig\shell\Verify` | (Default) | localized `VERIFY_WITH_AUTOFIRMA` (`Verificar con Autofirma`) |
    | `HKCR\.csig\shell\Verify\command` | (Default) | `$INSTDIR\Autofirma\Autofirma.exe verify -gui -i "%1"` |
    | `HKCR\.xsig` | (Default) | localized `XADES_SIGNATURE` (`Firma XMLDSig/XAdES`) |
    | `HKCR\.xsig\DefaultIcon` | (Default) | `$INSTDIR\Autofirma\ic_firmar.ico` |
    | `HKCR\.xsig\shell\Verify` | (Default) | `Verificar con Autofirma` (localized) |
    | `HKCR\.xsig\shell\Verify\command` | (Default) | `$INSTDIR\Autofirma\Autofirma.exe verify -gui -i "%1"` |
    | `HKCR\afirma` | (Default) | `URL:Afirma Protocol` |
    | `HKCR\afirma` | `URL Protocol` | `""` |
    | `HKCR\afirma\DefaultIcon` | (Default) | `$INSTDIR\Autofirma\ic_firmar.ico` |
    | `HKCR\afirma\shell\open\command` | (Default) | `$INSTDIR\Autofirma\Autofirma.exe "%1"` |

    - **Gotcha:** the executable paths in the `command` values are **not quoted** and the path contains spaces (`C:\Program Files\…`). It works through Windows' path heuristics but is an "unquoted path" weakness, so quote them in the reimplementation.
    - **Quirk:** `.csig`/`.xsig` (Default) is set to a human-readable text instead of a ProgID.
    - Only these two extensions get a verb. All files (`*`) get "Firmar con Autofirma".
12. Delete any `$INSTDIR\Autofirma\Autofirma_ROOT.cer` and `autofirma.pfx` from a previous install, which forces regeneration.
13. **Run the configurator:** `ExecWait '"$INSTDIR\Autofirma\AutofirmaConfigurador.exe" [-firefox_roots] -default_language <xx_YY> /passive'`. `-firefox_roots` is passed when the third checkbox was ticked; `/passive` is ignored. See §9.3.4.
14. **`DeleteCertificateOnInstall`** (crypt32 via `System::Call`):
    - Open `CertOpenStore(CERT_STORE_PROV_SYSTEM=10, …, CERT_STORE_OPEN_EXISTING_FLAG|CERT_SYSTEM_STORE_LOCAL_MACHINE (0x4000|0x20000), "ROOT")`.
    - Enumerate the store and delete every certificate whose **issuer** simple display name equals `"AutoFirma ROOT"`. NSIS `==` is case-insensitive, so this also matches `Autofirma ROOT`.
    - At this point the new CA is not yet in the store.
15. Sleep 2 s, then **`AddCertificateToStore("$INSTDIR\Autofirma\Autofirma_ROOT.cer")`**: `CryptQueryObject(CERT_QUERY_OBJECT_FILE, …, CONTENT_FLAG_ALL=16382, FORMAT_FLAG_ALL=14)`, then `CertOpenStore(… LOCAL_MACHINE … "ROOT")`, then `CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_ALWAYS=4)`. Errors (`"No fue posible abrir el almacén de certificados"`, `"No fue posible abrir el fichero de certificados"`) are computed but **ignored**.

**Browser integration on Windows:**
- **Chrome and Edge** trust the CA because it is in the **LocalMachine ROOT** store.
- **Firefox** gets the CA in each discovered profile's NSS DB (configurator). With the checkbox or `-firefox_roots` it also gets `security.enterprise_roots.enabled=true` in `user.js`.
- **No Chrome/Edge policies** are written: neither `AutoLaunchProtocolsFromOrigins` nor `ExternalProtocolDialogShowAlwaysOpenCheckbox` nor `URLAllowlist`, by any installer or by the configurator (verified by grep over the whole repo). **No Firefox `policies.json`** is written.
- The `afirma:` scheme is registered only through `HKCR\afirma`. Browsers show their standard "open external application" prompt.

#### 9.3.4 Windows configurator (`ConfiguratorWindows`)

Constants:

| Name | Value |
|---|---|
| `KS_FILENAME` | `autofirma.pfx` |
| `KS_PASSWORD` | `654321` |
| `CA_CERT_FILENAME` | `Autofirma_ROOT.cer` |
| `WAITING_TIME_IN_SECONDS` | 10 |
| `UNINSTALL_CERT_RETRIES` | 3 |

`configure(console)`:

1. Print `"Identificando directorio de aplicación..."` and `"  Directorio de aplicación: <appDir>"`. `appDir` is the directory of the running exe/jar; for JNLP, `%ALLUSERSPROFILE%\Autofirma` (created if needed, else `java.io.tmpdir`).
2. If `<appDir>\autofirma.pfx` **exists**, print `"Ya se encuentra instalado el certificado para la configuración del canal seguro, no se hará nada"` and skip to step 6. Otherwise continue.
3. Obtain the certificate files:
   - If both `-keystore_path` and `-certificate_path` are non-empty, print `ConfiguratorWindows.25` and copy them to `autofirma.pfx` and `Autofirma_ROOT.cer`. Copy errors print `ConfiguratorWindows.23` or `.24` and the run continues.
   - Otherwise print `"Generando certificado para la comunicación con el navegador web..."`, generate the CertPack (§9.2), print `ConfiguratorWindows.11`, and write `autofirma.pfx` and `Autofirma_ROOT.cer`.
   - **JNLP only:** show the message dialog `ConfiguratorWindows.17` (`"Se va a instalar el certificado SSL para la comunicación segura entre su navegador Web y la herramienta de firma electrónica. Por favor, dé permisos para su instalación en el siguiente diálogo."`). Then import into SunMSCAPI `KeyStore "Windows-ROOT"`, which is the **CurrentUser** Root store and makes Windows show its own confirmation, with alias `"CN=Autofirma ROOT"`. On failure ask `ConfiguratorWindows.0` with OK/Cancel to retry.
4. Print `ConfiguratorWindows.26`, then `ConfiguratorFirefoxWindows.uninstallRootCAMozillaKeyStore(appDir, console, 3)` to remove older copies (§9.3.5).
5. Print `"Importando certificado en el almacén de confianza de Mozilla Firefox..."`, then `installCACertOnMozillaKeyStores(appDir, console)`. If no profiles are found, print `ConfiguratorWindows.12` (`"No se ha detectado un perfil de Mozilla Firefox en el que instalar el certificado"`). If `-firefox_roots` is set, print `ConfiguratorWindows.22` and call `configureUseSystemTrustStore(true)`, which writes `user.js` (§9.3.5).
6. **PATH:**
   - Print `"Agregando ruta al PATH"`.
   - Copy the resource `windows/autofirma-addpath.cmd` to a temp file `script-*.cmd`.
   - Run `cmd.exe /c <tmp.cmd> <appDir>` with the working directory set to `appDir` and stderr merged. Wait at most 10 s; on timeout the process is destroyed and treated as exit code 1.
   - A non-zero exit raises an error and prints `"Error al agregar la ruta al PATH"`. Success prints `"Ruta agregada correctamente al PATH"`.
   - Script logic:
     1. Strip the trailing `\` from the target.
     2. `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path`. If it cannot be read, exit 1.
     3. If `;%SYSPATH%;` already contains `;<target>;` (case-insensitive `findstr /I`), exit 0.
     4. Otherwise append `;<target>` and `reg add … /v Path /t REG_EXPAND_SZ /d "<new>" /f`.
   - **Gotcha:** no `WM_SETTINGCHANGE` is broadcast, so already-running shells do not see the change. The original's purpose is to make `Autofirma`/`AutofirmaCommandLine` callable from a console.
7. Print `"Fin de la configuración"`.

`uninstall(console, pluginsManager)`:
1. Remove the CA from SunMSCAPI `Windows-ROOT` (CurrentUser view): load `<appDir>\Autofirma_ROOT.cer` and find its alias. If the file or alias is not found, use alias `"CN=Autofirma ROOT"`. `deleteEntry` if present.
2. `uninstallRootCAMozillaKeyStore(appDir, console, 3)`.
3. Uninstall every plugin (`PluginsManager(<alternativeDir>\plugins).getPluginsLoadedList()` then `uninstallPlugin` for each; see §7).
4. Recursively delete `%ALLUSERSPROFILE%\Autofirma`, best effort.
5. Run `windows/autofirma-removepath.cmd <appDir>`, which rebuilds the system `Path` without entries equal (case-insensitive, trailing `\` ignored) to the target and writes it back as `REG_EXPAND_SZ`.
6. `AutofirmaConfigurator*` then removes system preferences (§4).

#### 9.3.5 Firefox on Windows (`ConfiguratorFirefoxWindows`)

- **certutil:**
  - The resource `/windows/certutil.windows.zip` (NSS 3.12-era build, 2010) is extracted into `<appDir>\certutil\` if that directory does not exist. Contents: `certutil.exe, freebl3.chk, freebl3.dll, libnspr4.dll, libplc4.dll, libplds4.dll, nss3.dll, nssckbi.dll, nssdbm3.chk, nssdbm3.dll, nssutil3.dll, smime3.dll, softokn3.chk, softokn3.dll, sqlite3.dll, ssl3.dll`.
  - It must be a file and executable, otherwise the Firefox step is skipped with a warning.
  - The directory is never removed; it stays in the install dir.
- **User enumeration:**
  - `USERS_PATH` is the parent of `%PUBLIC%`, typically `C:\Users\`. Fallbacks: the parent of `user.home`, then `%SystemDrive%\Users\`. On XP it is the parent of `%ALLUSERSPROFILE%` with `Application Data\…`.
  - Every subdirectory except `Default` (case-insensitive) is examined.
  - `profiles.ini` is at `<user>\AppData\Roaming\Mozilla\Firefox\profiles.ini`.
- **Profile selection: only ONE profile per user** (`MozillaKeyStoreUtilities.getMozillaUserProfileDirectoryWindows` → `NSPreferences.getFireFoxUserProfileDirectory`). Parse `profiles.ini` sections `[General]`, `[Profile*]` (`Name`, `Path`, `IsRelative`, `Default`) and `[Install*]` (`Default=`, `Locked=`; if several, prefer the one with `Locked` declared). Choose:
  1. ini version 1: the first non-dummy profile that is *locked* (`parent.lock` exists, or a `lock` file or symlink on UNIX). Version ≥ 2: the profile whose `Path` equals `[Install*] Default`.
  2. Otherwise the non-dummy profile with `Default=1`.
  3. Otherwise the non-dummy profile directory with the newest mtime.
  4. Otherwise the first profile.
  
  A **dummy** profile has fewer than 10 entries, or neither a readable `key4.db` nor a readable `key3.db`. The resulting path is then normalised (`cleanMozillaUserProfileDirectoryWindows`).
- **DB type:** `sql:` is prefixed when `<profile>\pkcs11.txt` exists, otherwise the legacy dbm form is used.
- **Install command** (paths containing spaces are wrapped in `"`; the process is run directly, not via a shell):
  `certutil.exe -A -d [sql:]<profile> -i <appDir>\Autofirma_ROOT.cer -n "SocketAutoFirma" -t "C,,"`
- **Delete command:** `certutil.exe -D -d [sql:]<profile> -n "SocketAutoFirma"`. On failure it falls back to `-n "Autofirma ROOT"`. It is repeated `UNINSTALL_CERT_RETRIES=3` times per profile to remove duplicates.
- **Success detection:** stdin is closed immediately, and success means *no output at all* (stdout and stderr each read up to 256 lines × 1024 chars):
  - stdout starting with `Enter Password` means the profile has a master password:
    1. kill the process;
    2. prompt with `AOUIFactory.getPassword("Inserte la contraseña maestra de Firefox para la instalación de los certificados necesarios para la comunicación con Autofirma.")`, repeating until the value is non-empty;
    3. write the password (UTF-8) to `<appDir>\p<N>`, the first non-existing N;
    4. re-run with `-f <file>` inserted after the executable;
    5. delete the file silently.
  - Any other output is an error. During install the user is asked `ConfiguratorWindows.10` (`"El certificado de confianza para la comunicación entre Mozilla Firefox y Autofirma no ha podido instalarse… ¿Desea reintentar instalar este certificado?"`) with OK/Cancel and retries until success or cancel.
- **`security.enterprise_roots.enabled` (`configureUseSystemTrustStore(enable)`):** for every profile found (same one-per-user list), edit or create `<profile>\user.js`:
  - If it exists: rewrite it line by line, replacing every line containing `security.enterprise_roots.enabled` with `user_pref("security.enterprise_roots.enabled", true);\r\n`. If no such line exists, append `\r\n// Confianza en los certificados raices del almacen del sistema\r\n` followed by that line.
  - If it does not exist: create it with `// === PROPIEDADES PERSONALIZADAS DE CONFIGURACION ===\r\n`, the comment above, and the pref line.
  - Encoding is UTF-8 with CRLF.
  - Messages: `"Habilitando el uso de los certificados raíces de confianza del sistema en Mozilla Firefox."` (`ConfiguratorWindows.19`); `ConfiguratorWindows.20` when disabling.
  - No `network.protocol-handler.*` prefs are written on Windows.

#### 9.3.6 Launchers (launch4j) and bundled JRE

| Exe | Config | Header | Main | JVM options (64-bit) | JVM options (32-bit) | Other |
|---|---|---|---|---|---|---|
| `Autofirma.exe` | `Autofirma_launch4J_project_{64,32}.xml` | `gui` | jar manifest → `es.gob.afirma.standalone.SimpleAfirma` (wraps `jar\autofirma.jar`) | `-Xms512m -Xmx8g -Djdk.tls.maxHandshakeMessageSize=65536`; `requires64Bit=true` | `-Xms256m -Xmx1g -Djdk.tls.maxHandshakeMessageSize=65536`, initial heap 512 MB, max heap 1536 MB | **Splash** `splash.bmp`, `waitForWindow=true`, `timeout=10` s, `timeoutErr=false`. `chdir=.` |
| `AutofirmaCommandLine.exe` | `AutofirmaCommandLine_launch4J_project_*.xml` | **`console`** | `es.gob.afirma.standalone.CommandLineLauncher` | `-Xms512m -Xmx8g` | `-Xms256m -Xmx1g` | `requires64Bit=false` on both |
| `AutofirmaConfigurador.exe` | `Autofirma_launch4J_Configurador_project_*.xml` | `gui` | `es.gob.afirma.standalone.configurator.AutofirmaConfiguratorSilent` (wraps `jar\autofirmaConfigurador.jar`) | `-Xms512m -Xmx1g` | `-Xms256m -Xmx1g` | `stayAlive=true`. Manifest `AutofirmaConfigurator.manifest`, which requests `requestedExecutionLevel level="highestAvailable" uiAccess="False"` |

Common settings for all three launchers:
- JRE search path `./jre;%JAVA_HOME%;%PATH%`, `minVersion 1.8.0`;
- VersionInfo 1.10.0.0, company `Gobierno de España`, language `CASTILIAN_SPANISH`;
- Spanish launcher error texts (`jreNotFoundErr` = `"No se ha encontrado el Java Runtime Environment (JRE) de Autofirma ni ningún otro en el PATH del sistema."`, etc.).

**No launch4j `<singleInstance>` mutex is configured**, so the launcher does not enforce a single instance; any single-instance behaviour is in Java (§1).

Bundled JRE details:
- `java{32,64}\jre` is copied to `<appDir>\jre`.
- Its `conf/accessibility.properties` contains `assistive_technologies=com.sun.java.accessibility.AccessBridge` and `screen_magnifier_present=true`. This enables the Java Access Bridge, so Windows screen readers can read the Swing UI (§12).
- Before packaging, `certificados/insert_cacerts.bat` imports every file in `certificados/` into each bundled JRE's `lib/security/cacerts`: `keytool -importcert -noprompt -storetype JKS -storepass changeit -alias <filename>`. `insert_cacerts.sh` does the same for the macOS JREs `../macos/java_x64`, `java_aarch64` and `java_old`.
- These are Spanish trust-service CAs, so outbound HTTPS works to servers whose certificates chain to them: intermediate/trifásico servers, TSA, OCSP/CRL, config-file download, and the updater. The CAs, by provider:
  - **ACA** (Abogacía): CA1, CA2, CA3, CORP/TRUS csrs SHA256, Corporativos-2014, ROOT, Trusted-2014, raiz_csrs, trusted_csrs.
  - **ACC/CATCert** (Catalonia): clauEntitatCertificadoraCatcert, ec_ciutadania, ec_sectorpublic.
  - **ACCV** (Valencia): ACCVCA110/120/130 (+SHA2), ACCVRAIZ1.
  - **ANF**: root, secureserver.
  - **EADtrust**: root and subca, RSA 4096/8192 DV/OV and EV/PSD2 2019.
  - **FNMT**: AC Componentes Informáticos SHA256, AC FNMT Usuarios, AC Raíz FNMT-RCM (+SHA256), AC Representación, AC Sector Público, Servidores Seguros Tipo1/Tipo2, Unidades Sellado Tiempo.
  - **Firma Profesional**: ca1, caroot, caroot256, cualificados, infraestructura, secureweb2024.
  - **Izenpe**: root, ssl, ssldv.
  - **Logalty**: caroot03, qualifiedg2.
  - **USERTrust**: root and int.
  
  Rust equivalent: trust these roots in addition to the platform/webpki roots for the app's HTTP client.

#### 9.3.7 Windows EXE uninstaller (`Section "uninstall"`)

1. `SetShellVarContext all`. Loop until `firefox.exe` is closed, showing the `CLOSE_FIREFOX` message. Sleep 2 s.
2. `un.DeleteCertificate("$INSTDIR\Autofirma\Autofirma_ROOT.cer")`: read that certificate's subject and issuer simple names (default `"Autofirma ROOT"`/`"Autofirma ROOT"` if the file cannot be read). Delete from the **LocalMachine ROOT** store every certificate whose subject **and** issuer match (case-insensitive).
3. `ExecWait '"$INSTDIR\Autofirma\AutofirmaConfigurador.exe" -uninstall /passive'` (see §9.3.4).
4. Delete `$INSTDIR\Autofirma` (loop with 3 s sleeps). Then delete `$INSTDIR` itself if its path contains `Program Files (x86)\` or `Program Files\` or `Autofirma`.
5. Delete `$DESKTOP\Autofirma.lnk` and `$SMPROGRAMS\Autofirma`.
6. In the 64-bit view, then the 32-bit view (the 32-bit uninstaller uses the 64-bit view only on 64-bit Windows), `un.UninstallFromRegistry` deletes:
   - `HKLM\SOFTWARE\Autofirma` and `HKLM\…\Uninstall\Autofirma`;
   - `HKCR\*\shell\afirma.sign`, `HKCR\*\shell\afirma.verify` (legacy), `HKCR\.csig\shell\Verify`, `HKCR\.xsig\shell\Verify`, `HKCR\afirma`;
   - user preferences: `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\ui`, `…\standalone`, `…\core`, `…\plugin`, then `/ifempty` `…\es\gob\afirma`, `…\es\gob`, `…\es`.

   **Gotchas:**
   - `HKCR\.csig`, `HKCR\.xsig` and their `DefaultIcon` keys are left behind.
   - The HKCU deletion affects only the user running the (elevated) uninstaller.

#### 9.3.8 MSI deployment (`.wxs` + `AutofirmaGenerator.exe`)

WiX product:
- `Name="Autofirma"`, `Version="1.10"`, `Manufacturer="Gobierno de España"`;
- `UpgradeCode="{A6D90EBF-E089-4281-9269-AE5D20BA74D2}"`, the same for x86 and x64;
- `Language=1033`, `Codepage=1252`, `<MajorUpgrade AllowDowngrades="yes"/>`;
- `ALLUSERS=1`, `ARPNOREPAIR=yes`, `ARPNOMODIFY=yes`, `ARPPRODUCTICON=ic_launcher.ico`, `WixExitEarlyWithSuccess`.

The payload is installed into `[ProgramFiles64Folder|ProgramFilesFolder]\Autofirma\` and contains:
- `AutofirmaGenerator.exe`, the silent NSIS installer;
- `no_ejecutar_<x64|x86>.exe`, a prebuilt NSIS uninstaller named "do not run" so users don't start it by hand. It is a `Permanent="yes"` component so it survives until the uninstall custom action runs.

**Public MSI properties** (all `Secure="yes" Admin="yes"`; `"false"` means "not given"):

| Property | Default | Meaning |
|---|---|---|
| `CREATE_ICON` | `true` | Create the desktop shortcut (`false` disables it) |
| `FIREFOX_SECURITY_ROOTS` | `false` | `true` passes `-firefox_roots` |
| `CERTIFICATE_PATH` | `false` | Admin-provided CA file. Requires `KEYSTORE_PATH`; both must exist or install aborts |
| `KEYSTORE_PATH` | `false` | Admin-provided PKCS#12 (password `654321`) |
| `CONFIG_PATH` | `false` | Local path or `https:` URL of the preferences plist (see the `\`→`/` fix in §9.1.1) |
| `UPDATE_CONFIG` | `false` | `true` passes `-update_config` |
| `USE_SYSTEM_JRE` | `false` | `true` skips the bundled JRE. Install quits if no valid Java 8+ (64-bit for x64) is on PATH |
| `DEFAULT_LANGUAGE` | `false` | `es_ES`/`ca_ES`/`va_ES`/`gl_ES`/`eu_ES`/`en_US`. Passed as `-default_language` and also selects context-menu texts |
| `LANGUAGE_PATH` | `false` | Language pack ZIP; must exist or install aborts |

Example: `msiexec /i Autofirma_64_v1_10_installer.msi /qn FIREFOX_SECURITY_ROOTS=true DEFAULT_LANGUAGE=en_US CONFIG_PATH="https:\\intranet.example\autofirma.afconfig" UPDATE_CONFIG=true`

Custom actions:
- `QtExecInstall`: deferred, `Impersonate="no"` (runs as LocalSystem), `Return="check"`, before `InstallFinalize`, condition `NOT REMOVE`. Runs `AutofirmaGenerator.exe /S /FIREFOX_SECURITY_ROOTS=[…] /CREATE_ICON=[…] /CERTIFICATE_PATH=[…] /KEYSTORE_PATH=[…] /CONFIG_PATH=[…] /UPDATE_CONFIG=[…] /USE_SYSTEM_JRE=[…] /DEFAULT_LANGUAGE=[…] /LANGUAGE_PATH=[…]`.
- `QtExecUninstall`: deferred, no impersonation, after `InstallFiles`, condition `(NOT UPGRADINGPRODUCTCODE) AND (REMOVE="ALL")`. Runs `no_ejecutar_<platform>.exe /S`.

`AutofirmaGenerator.exe` (MSI NSIS) differs from the EXE installer:
- **`.onInit`:** reads the `/NAME=value` options and **aborts** in these cases:
  - only one of `KEYSTORE_PATH` or `CERTIFICATE_PATH` is set;
  - either file is missing;
  - `LANGUAGE_PATH` is missing.
- **No UI pages** (no custom page, no components page).
- **Silent exits:** on a 32-bit OS (x64 build), and when `USE_SYSTEM_JRE=true` but no valid Java is found.
- **Firefox is killed** (`nsProcess::KillProcess "firefox.exe"`) instead of waiting for the user to close it.
- **`RemoveOldVersions`** runs in **both** the 64- and 32-bit registry views:
  1. read `HKLM\SOFTWARE\Autofirma\InstallDir`;
  2. pick the uninstaller present there: `uninstall.exe`, `no_ejecutar_x64.exe` or `no_ejecutar_x86.exe`, the last one found winning;
  3. back up and restore the HKCU preferences as in the EXE installer;
  4. run `"<dir>\<uninst>" /S _?=<dir>`;
  5. `RMDir /r /REBOOTOK` the old dir if it differs from `$INSTDIR`.

  No version comparison is made. **Gotcha:** running as SYSTEM, the HKCU backup touches SYSTEM's hive, not the interactive user's.
- **Files:** `$INSTDIR\Autofirma` is deleted, then `no_ejecutar_x64.exe` is re-created in `$INSTDIR`, then the same files and JRE as the EXE installer are copied (JRE unless `USE_SYSTEM_JRE=true`).
- **Shortcuts:** desktop (unless `CREATE_ICON=false`) and Start menu `Autofirma.lnk` only, with no "Desinstalar" entry. No ARP `Uninstall\Autofirma` key and no `uninstall.exe`, because the MSI provides the uninstall entry.
- **Registry:** `HKLM\SOFTWARE\Autofirma` (`InstallDir`, `Version`) and the same HKCR keys. Texts depend on `DEFAULT_LANGUAGE`:

  | Locale | "Sign" verb | `.csig` | `.xsig` |
  |---|---|---|---|
  | es_ES/default | `Firmar con Autofirma` | `Firma binaria CMS/CAdES` | `Firma XMLDSig/XAdES` |
  | ca_ES, va_ES | `Signar amb Autofirma` | `Signatura binària CMS/CAdES` | `Signatura XMLDSig/XAdES` |
  | gl_ES | `Asinar con Autofirma` | `Firma binaria CMS/CAdES` | `Firma XMLDSig/XAdES` |
  | eu_ES | `Autofirmarekin sinatu` | `CMS/CAdES sinadura bitarra` | `Sinadura: XMLDSig/XAdES` |
  | en_US | `Sign with Autofirma` | `Binary signature CMS/CAdES` | `Signature XMLDSig/XAdES` |

  The "Verify" verb is always the hard-coded Spanish `Verificar con Autofirma`.
- **Configurator call:** `"…\AutofirmaConfigurador.exe" [-firefox_roots] [-certificate_path "<p>"] [-keystore_path "<p>"] [-config_path "<p>"] [-update_config] [-language_path "<p>"] [-default_language "<xx_YY>"] /passive`. It is followed by `DeleteCertificateOnInstall` and `AddCertificateToStore` exactly as in the EXE installer.

`forceUninstallFromReg.bat` (support tool):
1. Delete every `HKLM\Software\Classes\Installer\Products` subkey whose data matches `Autofirma`, which removes broken MSI registrations.
2. Run the `no_ejecutar_*.exe` uninstallers found under `C:\Program Files (x86)\Autofirma\` and `C:\Program Files\Autofirma\`.

Legacy/obsolete artefacts (not to reimplement):
- `afirma-standalone-installer/StandAlone.nsi` installs the old "Cliente @firma" StandAlone into `$PROGRAMFILES\StandAlone`; its context-menu lines are commented out.
- `afirma-windows-store` is a 2013 Windows 8 "Metro" C# app (`Package.appxmanifest` declares `windows.protocol` `afirma`). It is not part of current AutoFirma.

### 9.4 Linux

#### 9.4.1 Debian/Ubuntu package (`linux/instalador_deb`)

Built with `fakeroot dpkg-deb -Zgzip --build src AutoFirma_1_9_0.deb`.

`DEBIAN/control`:

```
Package: autofirma
Architecture: all
Section: utils
Priority: optional
Depends: libnss3-tools
Recommends: openjdk-17-jre
Version: 1.9.0
Maintainer: Gobierno de Espana <soporte.afirma@correo.gob.es>
Homepage: https://administracionelectronica.gob.es/ctt/clienteafirma
```

**Gotcha:** Java is only *Recommended*, but `postinst` calls `java` unconditionally. The package has no `Depends` on any JRE.

Files in the source tree (the jars are added at build time):

| Path | Content |
|---|---|
| `/usr/bin/autofirma` | `#!/bin/bash` + `java -Djdk.tls.maxHandshakeMessageSize=65536 -jar /usr/lib/Autofirma/autofirma.jar "$@"` |
| `/usr/lib/Autofirma/autofirma.jar`, `autofirmaConfigurador.jar` | app and configurator (added during packaging) |
| `/usr/lib/Autofirma/Autofirma.png` | icon (**the repo tree spells it `usr/lib/AutoFirma/AutoFirma.png`**; scripts and `.desktop` use `/usr/lib/Autofirma`, so the case must be fixed at build time) |
| `/usr/share/Autofirma/Autofirma.svg` | icon (repo: `usr/share/AutoFirma/AutoFirma.svg`) |
| `/usr/share/applications/afirma.desktop` | see below |
| `/usr/share/metainfo/es.gob.afirma.metainfo.xml` | AppStream: id `es.gob.afirma`, name `Autofirma`, `launchable desktop-id afirma.desktop`, provides binary `autofirma`, categories Office/Utilities/Signature/Java, licence `EUPL-1.1 OR GPL-2.0-only`, icon `/usr/share/Autofirma/Autofirma.svg`, release 1.9 (2025-01-27), requires `libnss3-tools` |
| `/etc/firefox/pref/AutoFirma.js` and `/usr/lib/firefox/defaults/pref/AutoFirma.js` | Firefox prefs (below) |
| `/usr/share/common-licenses/{eupl-1.1.txt,gpl-2.0.txt}`, `/usr/share/doc/AutoFirma/{copyright,EUPL-1.1.gz,GPL-2.0.gz}` | licences (EUPL-1.1 / GPL-2+) |

`afirma.desktop`:

```
[Desktop Entry]
Encoding=UTF-8
Version=1.9
Name=Autofirma
Type=Application
Terminal=false
Categories=Office;Utilities;Signature;Java
Exec=/usr/bin/autofirma %u
Icon=/usr/lib/Autofirma/Autofirma.png
GenericName=Herramienta de firma
Comment=Herramienta de firma
MimeType=x-scheme-handler/afirma;
StartupNotify=true
StartupWMClass=autofirma
Name[es_ES]=Autofirma
```

There is no file-type `MimeType` and no file-manager context-menu integration on Linux. The `afirma:` handler relies on the `.desktop` MimeType; `xdg-mime default afirma.desktop x-scheme-handler/afirma` is present in `postinst` but commented out.

Firefox system prefs file (`AutoFirma.js`, identical in both locations):

```
pref("network.protocol-handler.expose.afirma",false);
pref("network.protocol-handler.external.afirma",true);
pref("network.protocol-handler.warn-external.afirma",false);
pref("network.protocol-handler.app.afirma","/usr/bin/autofirma");
```

According to the comments in the file, `expose.afirma=false` is required on modern Firefox. Without it, `network.protocol-handler.expose-all=true` makes Firefox silently ignore `afirma:` links. `network.protocol-handler.app.*` no longer exists in recent Firefox and is kept only for old versions.

Maintainer scripts:
- **`preinst`:**
  - `if pgrep firefox; then pkill firefox; fi`
  - `mkdir -p /root/.local/share/applications/`
  - `mkdir -p /root/.config/`
- **`postinst`**, in order:
  1. `java -jar /usr/lib/Autofirma/autofirmaConfigurador.jar` with no args, which means install (§9.4.3). It runs as root, so `~` = `/root`.
  2. `echo "Generacion de certificados"`.
  3. If `/usr/lib/Autofirma/script.sh` exists: `chmod +x` it and run it. It installs the CA into the NSS DBs of every user (generated by the configurator; it has no shebang, so the shell falls back to `/bin/sh`).
  4. `echo "Instalacion del certificado CA en el almacenamiento de Firefox y Chrome"`.
  5. `openssl x509 -inform der -in /usr/lib/Autofirma/Autofirma_ROOT.cer -out /usr/lib/Autofirma/Autofirma_ROOT.pem`, then `mv …pem …/Autofirma_ROOT.crt`.
  6. If `/usr/share/ca-certificates/Autofirma` exists, delete it. Then `mkdir` it and copy `Autofirma_ROOT.crt` into it **and** into `/usr/local/share/ca-certificates/Autofirma_ROOT.crt`.
  7. `update-ca-certificates`; `echo "Instalacion del certificado CA en el almacenamiento del sistema"`.
  8. If `/etc/icecat` exists: create `/etc/icecat/pref` if missing and `ln -s /etc/firefox/pref/AutoFirma.js /etc/icecat/pref/AutoFirma.js`. Same for `/etc/firefox-esr`.
  9. `rm /usr/lib/Autofirma/script.sh` and `rm /usr/lib/Autofirma/Autofirma_ROOT.crt`. Exit 0.
  
  `uninstall.sh`, `autofirma.pfx` and `Autofirma_ROOT.cer` remain in `/usr/lib/Autofirma`.
- **`prerm`:**
  1. Kill Firefox.
  2. Remove `/etc/icecat/pref/Autofirma.js` and `/etc/firefox-esr/pref/Autofirma.js`. **Gotcha:** the case differs from the `AutoFirma.js` links created in `postinst`, so the links are never removed.
  3. If `/usr/lib/Autofirma/uninstall.sh` exists, `chmod +x` and run it, which removes the CA from every NSS DB recorded at install.
  4. Delete `/usr/share/ca-certificates/Autofirma` and `/usr/local/share/ca-certificates/Autofirma_ROOT.crt`.
  5. Delete `uninstall.sh`, `autofirma.pfx` and `Autofirma_ROOT.cer` from `/usr/lib/Autofirma`.
  6. `update-ca-certificates`.
  
  **Gotcha:** the deb never runs `autofirmaConfigurador.jar -uninstall`, so system preferences and installed plugins are not removed.
- **`postrm`:** `echo "Desinstalación completada con exito"`.

#### 9.4.2 RPM packages (Fedora `instalador_rpm_fedora`, openSUSE `instalador_rpm_suse`)

Built with `rpmbuild -bb SPECS/autofirma.spec` and signed with `rpm --addsign RPMS/noarch/*.rpm` (Fedora).

Common header: `Name: autofirma`, `BuildArch: noarch`, `AutoReqProv: no`, `License: GPLv2+ or EUPL 1.1`, `Requires: bash`, plus `Requires: nss-tools` (Fedora) or `mozilla-nss-tools` (SUSE). Version is `1.9` (Fedora) or `1.10` (SUSE). **There is no Java requirement.**

Installed files (`%{_libdir}` is e.g. `/usr/lib64` on x86_64 build hosts; **the directory is lowercase `autofirma`**):
- `%{_libdir}/autofirma/{autofirma.png, autofirma.jar, autofirmaConfigurador.jar}`;
- SUSE also installs `autofirma.svg`;
- `%{_bindir}/autofirma`, which contains `java -Djdk.tls.maxHandshakeMessageSize=65536 -jar %{_libdir}/autofirma/autofirma.jar "$@"`;
- the metainfo file (Fedora `%{_metainfodir}`; SUSE `/usr/share/metainfo/`);
- `%{_libdir}/firefox/defaults/pref/autofirma.js`, which contains **only** `app.afirma=/usr/bin/autofirma`, `warn-external.afirma=false` and `external.afirma=true`, with **no `expose.afirma`**.

The `.desktop` file is written to `/usr/share/applications/autofirma.desktop`: in Fedora at build time; in SUSE generated in `%post`, with localised `GenericName`/`Comment` and also copied to `/usr/local/share/applications/`. Contents:

```
Exec=java -Djdk.tls.maxHandshakeMessageSize=65536 -jar %{_libdir}/autofirma/autofirma.jar %u
Name=Autofirma   (SUSE: AutoFirma)
Icon=%{_libdir}/autofirma/autofirma.png
MimeType=x-scheme-handler/afirma
```

**Gotcha:** the metainfo refers to `afirma.desktop` but the file is `autofirma.desktop`.

Scriptlets:
- **`%pre`:** kill Firefox.
- **`%post`:**
  1. **SUSE only:** compute the locale from `$LANGUAGE`/`$LANG`. **Gotcha:** the English test compares `${CURRENT_LANG:1:2}` (wrong offset). Supported values are en→`en_US`, ca→`ca_ES`, eu→`eu_ES`, gl→`gl_ES`, `ca@valencia`→`va_ES`, else `es_ES`. Then write the `.desktop` file.
  2. `java -Djava.awt.headless=true -jar %{_libdir}/autofirma/autofirmaConfigurador.jar -install`, plus `-default_language "$AFIRMA_LOCALE"` on SUSE.
  3. Register the scheme as default:
     - If `/usr/share/applications/mimeapps.list` exists, append `x-scheme-handler/afirma=autofirma.desktop`; otherwise create it with `[Default Applications]` + that line.
     - **SUSE also** appends to `/usr/share/applications/gnome-mimeapps.list` (if present), to `/usr/local/share/applications/mimeapps.list` (create if missing) and to `/usr/local/share/applications/gnome-mimeapps.list` (if present).
  4. If `%{_libdir}/autofirma/script.sh` exists, `chmod +x` and run it.
  
  **Gotcha:** RPMs do **not** install the CA into the system trust store (no `update-ca-trust`). Only NSS DBs are configured.
- **`%preun`:** only when `$1 -eq 0` (a real uninstall, not an upgrade): `java -Djava.awt.headless=true -jar …/autofirmaConfigurador.jar -uninstall`. Then, if `uninstall.sh` exists, kill Firefox, `chmod +x` and run it.
- **`%postun`:** only when `$1 -eq 0`: remove the `x-scheme-handler/afirma=autofirma.desktop` line from every mimeapps list written above (`sed -i '/x-scheme-handler\/afirma=autofirma.desktop/d' …`), then `rm -r %{_libdir}/autofirma` and `echo "Desinstalación completada con exito"`.

#### 9.4.3 Linux configurator (`ConfiguratorLinux` + `ConfiguratorFirefoxLinux`)

**The Linux configurator does not touch any store directly.** It generates files and writes two shell scripts for the package scripts to run as root. Constants: `KS_FILENAME=autofirma.pfx`, `FILE_AUTOFIRMA_CERTIFICATE=Autofirma_ROOT.cer`, `KS_PASSWORD=654321`, `INSTALL_SCRIPT_NAME=script.sh`, `UNINSTALL_SCRIPT_NAME=uninstall.sh`. Messages go only to the log (`ConfiguratorLinux.*`).

`configure()`:

1. `appDir` = the configurator jar's directory (JNLP: `~/.afirma/Autofirma`).
2. User homes: run `cut -d: -f6 /etc/passwd` and keep the distinct lines whose lowercase form contains `home/`. Up to 2048 lines × 2048 chars are read.
   - **Gotcha:** this excludes `/root` and homes outside `*home/*` (e.g. `/srv/users/x`), and includes system accounts whose home is under `/home`.
3. If `<appDir>/autofirma.pfx` already exists, log `ConfiguratorLinux.14` and do nothing more. Otherwise:
   1. Generate the CertPack. Write `autofirma.pfx` and `Autofirma_ROOT.cer` (DER) to `appDir`.
   2. **certutil choice:** run `ProcessBuilder("certutil").start()`. If that succeeds, use `certutil` from PATH (package dependency `libnss3-tools`/`nss-tools`). Otherwise extract `/linux/certutil.linux.zip` into `<appDir>/certutil/` and use the absolute path.
      - The zip contains a 2010 NSS build: `certutil`, `libnspr4.so`, `libnss3.so`, `libnssutil3.so`, `libplc4.so`, `libplds4.so`, `libsmime3.so`, `libssl3.so`, `libsoftokn3.so` (+`.chk`), `libsqlite3.so`, `libfreebl3.so` (+`.chk`), `libnssckbi.so`, `libnssdbm3.so` (+`.chk`), and many static `.a` files.
      - **Gotcha:** no `LD_LIBRARY_PATH` is set in the Linux scripts, so the bundled binary probably cannot find its libraries.
   3. **Chrome/Chromium NSS DBs** (`createScriptsToSystemKeyStore`): for every user home and each sub-path `/.pki/nssdb` and `/snap/chromium/current/.pki/nssdb`, if the directory exists **and** already holds an NSS store (`cert9.db`, `pkcs11.txt` or `cert8.db`), add:
      - to `script.sh`: `<certutil> -d sql:<home><sub> -A -n "SocketAutoFirma" -i <appDir>/Autofirma_ROOT.cer -t "TCP,TCP,TCP"`
      - to `uninstall.sh`: `<certutil> -D -d sql:<home><sub> -n "SocketAutoFirma"`

      Uninitialised directories are skipped, because `certutil` would *create* a store the browser did not make (a recent fix: "No fabricar el almacén NSS de un perfil que el navegador no ha abierto").
   4. **Firefox profiles** (`createScriptsToMozillaKeyStore`):
      - For each user, use `<home>/snap/firefox/common/.mozilla/firefox/profiles.ini` if it exists, **otherwise** `<home>/.mozilla/firefox/profiles.ini`. These are exclusive: when snap is present the classic profile is ignored.
      - Every line starting with `Path=` gives a profile dir = `<dir of profiles.ini>/` + value. `IsRelative` is ignored, so absolute paths break. It is kept if it is a directory.
      - If there is no `profiles.ini` or no profiles, throw `MozillaProfileNotFoundException`, logged as `ConfiguratorLinux.12`.
      - For each profile dir that is a directory **and** has an NSS store (same three files):
        - `sql:` prefix only if `pkcs11.txt` exists;
        - to `script.sh`: `<certutil> -A -d [sql:]<profile> -i <appDir>/Autofirma_ROOT.cer -n "SocketAutoFirma" -t "C,,"`
        - to `uninstall.sh`: `<certutil> -D -d [sql:]<profile> -n "SocketAutoFirma"`
      - If a write fails, ask `ConfiguratorWindows.10` with OK/Cancel and retry.
   5. Script format: one command per line, tokens joined by single spaces, a space before the newline, paths escaped by replacing `" "` with `"\ "`. Files are opened in **append** mode, so re-runs accumulate lines. There is no shebang.
4. Log `ConfiguratorLinux.8`. If `GraphicsEnvironment` cannot be initialised (headless JRE), warn that the GUI cannot run.

**Not handled on Linux:**
- Flatpak Firefox (`~/.var/app/org.mozilla.firefox/.mozilla/firefox`);
- the XDG Firefox profile location (`~/.config/mozilla/firefox`);
- Flatpak Chrome/Chromium;
- Firefox `user.js`/enterprise roots (`-firefox_roots` is ignored on Linux);
- per-user `xdg-mime` registration;
- users created after installation (the "Restore configuration" feature of §10 covers the current user).

A reimplementation should add the missing locations.

`uninstall()` (called by the RPM `%preun` only):
1. Uninstall plugins from `<alternativeDir>/plugins`. The process runs as root, so this is `/root/.afirma/Autofirma/plugins`.
2. Recursively delete `~/.afirma/Autofirma` (root's).

Certificates are removed by `uninstall.sh` and the package scripts, not here.

### 9.5 macOS

#### 9.5.1 Package (`.pkg` built with *Packages*)

- **Three projects:**

  | Project | Package name | Notes |
  |---|---|---|
  | `Autofirma_Packages_aarch64` | `Autofirma_1_10_aarch64` | host architectures `i386`, `arm64` |
  | `Autofirma_Packages_x64` | `Autofirma_1_10_x64` | |
  | `Autofirma_Packages_for_old_systems` | `Autofirma_1_10_x64_java_11` | bundles Java 11 |

- **Package settings:** identifier `es.gob.afirma`, version `1.10`, `AUTHENTICATION=1` (administrator required), not relocatable.
- **Payload:** `/Applications/Autofirma.app`, owner root, group admin (gid 80), mode 0755. `/Applications` is 0775.
- **Licences:** English, Catalan and Spanish (`resources/licencia_*.txt`).
- **`scripts/postinstall`** (runs as root):
  1. `CURRENT_USER=$USER`
  2. `PRE_LANG=$(sudo -u $CURRENT_USER defaults read .GlobalPreferences AppleLanguages | tr -d "[:blank:]()\"," | tr "-" "_" | sed '/^$/d' | head -n 1)`, falling back to `$LANG`.
  3. Map the first two letters: `en`→`en_US`, `ca`→`ca_ES`, `eu`→`eu_ES`, `gl`→`gl_ES`, `va`→`va_ES`, anything else → `es_ES`. Unset → `en_US`.
  4. Run `sudo /Applications/Autofirma.app/Contents/Resources/Home/bin/java -jar /Applications/Autofirma.app/Contents/Resources/JAR/autofirmaConfigurador.jar -install -default_language "$AFIRMA_LOCALE"`. This uses the GUI configurator **without `-headless`**, so dialogs and the graphical console appear.
  5. (aarch64/x64 only, commented out: reset the Launchpad DB and `killall Dock`.) `exit 0`.
- **No uninstaller package** is provided. `ConfiguratorMacOSX.uninstall` exists but must be invoked manually: `java -jar autofirmaConfigurador.jar -uninstall`.

#### 9.5.2 App bundle and launcher (`macos/Lanzador`)

`Autofirma.app` is a small Objective-C launcher (Xcode project `Autofirma.xcodeproj`, `main.m`, `AppDelegate.m`, `MainMenu.xib`) plus resources:
- `Contents/Resources/Home/`: the bundled JRE;
- `Contents/Resources/JAR/autofirma.jar`, `autofirmaConfigurador.jar`, `icon.icns`, `libJavaHelpHook.jnilib`;
- `Contents/Resources/AfirmaHelp/`: an Apple Help Book named `"Ayuda de Autofirma"`, with pages covering the license, command line, menus (plugins, preferences, restore), screens and the dialogs for trusted certificates, proxy, the domain whitelist and the visible PDF signature.

Per `macos/README.txt`, the NSS libraries in `macos/nss/` (`libmozglue.dylib`, `libnss3.dylib`, `libsoftokn3.dylib`, which reference each other through `@executable_path`) must be copied into the bundled JRE's executable directory so the Firefox keystore can be accessed.

`Info.plist`:

| Key | Value |
|---|---|
| `CFBundleIdentifier` | `es.gob.afirma.simpleafirma.osx` |
| `CFBundleURLTypes` | one entry: `CFBundleURLName` = `Protocolo de invocación de Autofirma`, `CFBundleURLSchemes` = `[afirma]` |
| `LSUIElement` | `true`, so the launcher has no Dock icon; the Java process shows its own, named via `-Xdock:name` |
| `LSMinimumSystemVersion` | `10.13` |
| `CFBundleShortVersionString` | `1.9` |
| `CFBundleIconFile` | `JAR/icon.icns` |
| `CFBundleHelpBookFolder` / `CFBundleHelpBookName` | `AfirmaHelp` / `Ayuda de Autofirma` |
| `CFBundleDevelopmentRegion` | `es` |
| `NSHumanReadableCopyright` | `Copyright © 2025 Gobierno de España.` |

There are **no `CFBundleDocumentTypes`**, so macOS has no file associations, and there is no Finder Services/context menu.

`AppDelegate` behaviour:
- In `awakeFromNib`, register an Apple Event handler for `kInternetEventClass/kAEGetURL`.
- `applicationDidFinishLaunching` calls `launch(nil)`; each GetURL event calls `launch(url)`.
- `launch()`:
  1. `chdir($HOME)`.
  2. Start `<bundle>/Contents/Resources/Home/bin/java -Xms1024M -Xmx2048M -Djdk.tls.maxHandshakeMessageSize=65536 --add-exports java.desktop/com.apple.eawt=ALL-UNNAMED -Dcom.apple.macos.useScreenMenuBar=true -Xdock:name=Autofirma -Xdock:icon=<bundle>/Contents/Resources/JAR/icon.icns -Djava.library.path=<bundle>/Contents/Resources/JAR -jar <bundle>/Contents/Resources/JAR/autofirma.jar [url]`, with stdout and stderr sent to `/dev/null`.
  3. Sleep 5 s, then `[NSApp terminate:]`.
- Exceptions are shown in a critical `NSAlert`.
- **Quirk:** each launch spawns a new JVM. When the app is opened by URL, both `didFinishLaunching` (no args) and the URL handler may start a JVM. A reimplementation should handle `kAEGetURL` in-process and forward to the running instance.

#### 9.5.3 macOS configurator (`ConfiguratorMacOSX` + `ConfiguratorFirefoxMac`)

Constants:

| Name | Value |
|---|---|
| `KS_FILENAME` | `/autofirma.pfx` |
| `SSL_CER_FILENAME` | `/autofirma.cer` |
| `MACOSX_CERTIFICATE` | `/Autofirma_ROOT.cer` |
| `KS_PASSWORD` | `654321` |
| `CERT_CN` | `127.0.0.1` |
| `CERT_CN_ROOT` | `Autofirma ROOT` |
| `GET_USERS_COMMAND` | `dscacheutil -q user` |

`configure(console)`:

1. **User homes:**
   - Write `dscacheutil -q user` to a temp script `scriptGetUsers*.sh` (chmod 0777).
   - Run it via `osascript -e 'do shell script "<file>"'` (`ShellScript.run`, non-admin). The temp script is deleted after it runs.
   - Keep the lines starting with `dir: /Users/` and strip `dir: `. The result is a set. Since macOS 15.1, apps also appear as users, which is why only `/Users/` homes are kept.
2. Print `ConfiguratorMacOSX.2/3`. `resourcesDir` = `$HOME/Library/Application Support/Autofirma` (created with 0777).
3. **`configureSSL`:**
   1. Create temp `installCerScript*.sh` (0777) and chmod 0777 every file in `resourcesDir`.
   2. Generate the CertPack. Write `Autofirma_ROOT.cer` (CA), `autofirma.pfx` and `autofirma.cer` (leaf) to `resourcesDir`.
   3. **Close Firefox:** while `ps aux` lists `Firefox.app`, `FirefoxNightly.app` or `FirefoxDeveloperEdition.app`, show a modal warning: title `"Almacén de Firefox bloqueado"`, text `"Cierre el navegador Mozilla Firefox para continuar con la instalación de Autofirma."`.
   4. **Keychain password (`getKeyChainPhrase`):**
      1. First try the literal `"dummy"` with `security unlock-keychain -p dummy`. This succeeds when no password is needed, e.g. as root.
      2. If stderr contains `password`, prompt with `"Inserte su contraseña para el acceso a los certificados del Llavero."` (`ConfiguratorMacOSX.27`). After a wrong password the prompt is `ConfiguratorMacOSX.28` (`"Contraseña incorrecta. …"`).
      3. If the user cancels, confirm with `ConfiguratorMacOSX.29`/`.30` (Yes = abort the configurator with an `AOCancelledOperationException`).
      4. Other unlock errors return `"dummy"`.
   5. Print `"Se desinstalan versiones anteriores de los certificados"`. **`uninstallProcess`** (repeated with a new password on `InvalidPasswordException`):
      1. For CN `127.0.0.1` and then `Autofirma ROOT`, repeat until not found:
         1. `sudo -S security find-certificate -c <CN> -Z`, with the password written to stdin.
         2. On exit 0, parse the value after `hash:` up to the end of the line, then run `sudo -S security delete-certificate -Z <hash> -t`.
         3. Exit ≠ 0 with stderr containing `SecKeychainSearchCopyNext` means none are left. Stderr containing `password` raises `InvalidPasswordException`.
         
         **Quirk:** `-c` is a substring match, so other certificates whose name contains `127.0.0.1` would also be deleted.
      2. Remove the certificate from the Firefox profiles of all users (script below, run with administrator privileges).
   6. Show the dialog `ConfiguratorMacOSX.20` (`"Se va a instalar el certificado SSL para la comunicación segura entre su navegador Web y la herramienta de firma electrónica. Se necesitarán permisos de administrador para completar esta operación."`). Print `ConfiguratorMacOSX.6`.
   7. **Trust in the System keychain:**
      - `sudo -S security -i add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <resourcesDir>/Autofirma_ROOT.cer`, then print `"Certificado de CA importado."`.
      - `sudo -S security -i add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain <resourcesDir>/autofirma.cer`, then print `"Certificado SSL importado."`.
      - The password is written to sudo's stdin. A non-zero exit with stderr containing `password` raises `SecurityException`; otherwise `KeyChainException`.
      - On failure print `ConfiguratorMacOSX.34` and show the error `ConfiguratorMacOSX.25` (`"No se han podido importar los certificados SSL en el Llavero… utilice la función "Restaurar instalación""`).
   8. Print `"Se va a instalar el certificado en el almacen de Mozilla Firefox"`. Run **`ConfiguratorFirefoxMac.installOnMozillaKeyStore`**, then `MozillaKeyStoreUtilitiesOsX.configureMacNSS(<system NSS dir>)`, then run the script file once more with admin rights and delete it.
      - `configureMacNSS` first tries `System.load` of `libmozglue.dylib`, `libnss3.dylib` and `libsoftokn3.dylib`.
      - If that fails, it uses administrator AppleScript to `mkdir /usr/local/lib` (if missing) and `ln -s <nssDir>/<lib> /usr/local/lib/<lib>` for `libmozglue, libmozutils, libnspr4, libplds4, libplc4, libnssutil3, libmozsqlite3, libnss3` (`.dylib`).
      - The NSS dir is searched in `/Applications/Firefox.app/Contents/MacOS`, `/lib`, `/usr/lib`, `/usr/lib/nss`, `/Applications/Minefield.app/Contents/MacOS`.
4. **Firefox enterprise roots:**
   - Headless: use the `-firefox_roots` flag.
   - GUI: ask Yes/No `"¿Desea que se configure Firefox para que confíe en los certificados raíz del llavero del sistema?"` (title `"Integración con Firefox"`).
   - If yes, print `ConfiguratorMacOSX.22` and write `user.js` in every profile, with the same algorithm and texts as on Windows (§9.3.5).
5. Print `"Fin de la configuración"`.

`ConfiguratorFirefoxMac` details:
- **certutil:** `<resourcesDir>/certutil/certutil`, extracted from `/osx/certutil.osx.zip` if missing, and given execute permissions. The zip contains `certutil`, `libnspr4`, `libnss3`, `libnssutil3`, `libplc4`, `libplds4`, `libsmime3`, `libssl3`, `libfreebl3`, `libnssckbi`, `libnssdbm3`, `libsoftokn3`, `libsqlite3` (`.dylib`) and `libjss4.jnilib`, from a 2010 build.
- **Profiles:** for each user home, read `<home>/Library/Application Support/firefox/profiles.ini` (lowercase `firefox`, which works on case-insensitive APFS). Every `Path=` line gives `<iniDir>/<value>` (always treated as relative) if it is an existing directory. Unlike Linux, there is **no** "store already initialised" check.
- **Install script, per profile:**
  1. The temp script is overwritten with `export PATH=$PATH:<certutilDir>`.
  2. Then it is appended with `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<certutilDir>` and `<certutil> -A -d [sql:]<profile> -i <resourcesDir>/Autofirma_ROOT.cer -n "SocketAutoFirma" -t  "C,,"`.
  3. It is executed with `osascript -e 'do shell script "<script>" with administrator privileges'`.
  
  The console prints `"Se importa el certificado en el perfil: <name>"`, or `ConfiguratorMacOSX.36` on error. Script generation errors ask `ConfiguratorWindows.10` to retry.
- **Uninstall script, per profile:** after the same two `export` lines: `max=$(<certutil> -L -d <ref> | grep Autofirma | wc -l);for ((i=0; i<$max; i++));do <certutil> -D -d <ref> -n "SocketAutoFirma";done`. It is executed as administrator.
- Paths are escaped with `" "` → `"\ "`.

`uninstall(console, pluginsManager)`:
1. Get the keychain password.
2. `uninstallProcess` (keychain and Firefox, as above).
3. Uninstall plugins from `<alternativeDir>/plugins`.
4. Recursively delete `$HOME/Library/Application Support/Autofirma`.

**Gotcha (macOS):** the configurator runs as root from `postinstall`. `$HOME` (used for `resourcesDir`) is then whatever `sudo` preserves, typically the installing user's home on macOS. The running app looks for `autofirma.pfx` in **the current user's** `~/Library/Application Support/Autofirma`, so other users of the machine need "Restore configuration" (§10).

### 9.6 Configuration file import at install time (`-config_path`)

This is `ConfigUpdaterManager.savePrefsConfigFile(url, allowUpdates)`:

1. Read the file:
   - if the path starts with `https:` (case-insensitive), download it with `DataDownloader.downloadData(url, gzipped=false, ignoreSSLSecurity=true)`, i.e. **with TLS certificate validation disabled**;
   - otherwise read the local file.
2. Compute `ConfigDataInfo`: SHA-256 of the bytes, **upper-case** hex without separators (`AOUtil.hexify(hash, false)`).
3. `PreferencesManager.clearAllSystemPrefs()`, then `PreferencesPlistHandler.importSystemPreferencesFromXml(bytes)`. The format is an XML plist; a `smartcards` dictionary goes to `KeyStorePreferencesManager`; the rest is validated and stored as **system** preferences. See §4.
4. Store the internal system preferences in node `/es/gob/afirma/standalone/ui/internalpreferences`. It is the system root if writable, otherwise the user root:

   | Key | Value |
   |---|---|
   | `configFileUrl` | the given path or URL |
   | `allowUpdateConfig` | `true` only if `-update_config` was given **and** the URL is `https://`; otherwise the key is removed |
   | `configFileSHA256` | the hash |
   | `configDate` | formatted with `SimpleDateFormat("YYYYMMdd")`. **Gotcha:** `YYYY` is the *week-year*, so dates around New Year can compare wrongly; use `yyyyMMdd` semantics. |

5. Flush. Errors are logged and swallowed, so the install still succeeds.

At app start-up (`SimpleAfirma`), `ConfigUpdaterManager.needCheckConfigUpdates()` returns true when all of these hold:
- the system node has `allowUpdateConfig=true`;
- the URL is `https://`;
- `configDate` is missing or older than today.

When it does, `updatePrefsConfigFile()` downloads the file again. If the SHA-256 differs from `configFileSHA256`, it clears and re-imports the system prefs and updates the hash. In every case it updates `configDate`.

### 9.7 Browser integration summary

| Aspect | Windows | Linux | macOS |
|---|---|---|---|
| `afirma:` scheme | `HKCR\afirma` (§9.3.3) | `.desktop` `MimeType=x-scheme-handler/afirma` (deb `afirma.desktop`, rpm `autofirma.desktop`); RPMs also write `mimeapps.list` defaults | `CFBundleURLTypes` in `Autofirma.app` |
| Firefox scheme prefs | none | deb: `/etc/firefox/pref/AutoFirma.js` + `/usr/lib/firefox/defaults/pref/AutoFirma.js` (`expose=false`, `external=true`, `warn-external=false`, `app=/usr/bin/autofirma`), symlinked for icecat and firefox-esr; rpm: `%{_libdir}/firefox/defaults/pref/autofirma.js` (no `expose`). Snap and flatpak Firefox ignore these system pref dirs | none |
| CA in OS store | LocalMachine `ROOT` (NSIS crypt32). JNLP: CurrentUser Root via Java | deb only: `/usr/local/share/ca-certificates/Autofirma_ROOT.crt` (+ `/usr/share/ca-certificates/Autofirma/`) + `update-ca-certificates`; rpm: none | System keychain: CA `trustRoot` + leaf `trustAsRoot` |
| CA in Firefox | NSS of **one profile per Windows user**, nickname `SocketAutoFirma`, `C,,` | NSS of **every profile** in `profiles.ini` of every `/home` user (snap location takes precedence), only if the store exists | NSS of every profile of every `/Users` user |
| Chrome/Chromium/Edge | via Windows ROOT | `~/.pki/nssdb` and `~/snap/chromium/current/.pki/nssdb` (`TCP,TCP,TCP`), if they exist | via keychain |
| Firefox enterprise roots | `user.js` `security.enterprise_roots.enabled=true` when checkbox, `-firefox_roots` or `FIREFOX_SECURITY_ROOTS=true` | not supported | `user.js` when the user says yes or `-firefox_roots` with `-headless` |
| Chrome/Edge policies (`AutoLaunchProtocolsFromOrigins`, `ExternalProtocolDialogShowAlwaysOpenCheckbox`, `URLAllowlist`…) | **not set anywhere** | **not set** | **not set** |
| Firefox `policies.json` | **not used** | **not used** | **not used** |
| Firefox must be closed | prompt loop (EXE) / killed (MSI) | `pkill firefox` in preinst/prerm (`%pre`/`%preun`) | modal prompt loop |

### 9.8 Uninstall summary

| Step | Windows EXE | Windows MSI | Debian | RPM | macOS |
|---|---|---|---|---|---|
| CA removed from OS store | LocalMachine ROOT (matching subject+issuer of `Autofirma_ROOT.cer`, default `Autofirma ROOT`) + configurator removes it from CurrentUser `Windows-ROOT` | same (via `no_ejecutar_*.exe`) | `/usr/local/share/ca-certificates/Autofirma_ROOT.crt` + `/usr/share/ca-certificates/Autofirma/` + `update-ca-certificates` | n/a | only via manual `-uninstall`: `security delete-certificate` for CN `127.0.0.1` and `Autofirma ROOT` |
| CA removed from NSS | configurator: `certutil -D` ×3 per Firefox profile (`SocketAutoFirma`, fallback `Autofirma ROOT`) | same | `uninstall.sh` (Firefox profiles + `.pki/nssdb`) | `uninstall.sh` | manual `-uninstall` |
| Plugins removed | configurator | configurator | **no** | configurator (`%preun`) | manual |
| System preferences removed | configurator (`removeSystemPrefs`) | configurator | **no** | configurator | manual |
| User preferences removed | `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\{ui,standalone,core,plugin}` | same | no | no | no |
| PATH entry removed | `autofirma-removepath.cmd` | same | n/a | n/a | n/a |
| Program files removed | `RMDir /r` | MSI + NSIS | dpkg + prerm deletes generated files | `rm -r %{_libdir}/autofirma` | n/a |
| Protocol and file associations removed | `HKCR\afirma`, verbs (not `.csig`/`.xsig` roots) | same | `.desktop` removed by dpkg | mimeapps lines removed with `sed` | n/a |

### 9.9 Notes for the Rust reimplementation

- Use a single native "configurator" binary or sub-command for all three OSes, with the same flags as §9.1.1 so existing MSI/MDM tooling keeps working (`-install`, `-uninstall`, `-firefox_roots`, `-certificate_path`, `-keystore_path`, `-config_path`, `-update_config`, `-language_path`, `-default_language`, `-headless`, `-keep_open`). Keep the MSI public properties of §9.3.8.
- Generate the certificates natively (RSA-2048 or ECDSA P-256; positive random serial; leaf EKU `serverAuth`; SAN `IP:127.0.0.1`, `IP:::1`, `DNS:localhost`). Keep the `CN=Autofirma ROOT` and nickname `SocketAutoFirma` conventions so old artefacts can be found and cleaned.
- Trust installation per OS:
  - Windows: `CertAddCertificateContextToStore` on LocalMachine `ROOT`.
  - macOS: `SecTrustSettingsSetTrustSettings` / `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`.
  - Linux: the distro trust anchors (`/usr/local/share/ca-certificates` + `update-ca-certificates` on Debian; `/etc/pki/ca-trust/source/anchors` + `update-ca-trust` on Fedora; `/etc/pki/trust/anchors` + `update-ca-certificates` on SUSE), **and** every NSS DB: Firefox classic/snap/flatpak/XDG profiles and `~/.pki/nssdb`, using system `certutil`.
  - Do not create NSS DBs that do not exist.
- The original sets **no** Chrome/Edge policies and no Firefox `policies.json`. Adding them (e.g. Firefox `Certificates.ImportEnterpriseRoots`, Chrome `AutoLaunchProtocolsFromOrigins`) would go beyond parity and should be opt-in for administrators.
- Fix the known quirks listed above:
  - unquoted command paths;
  - case mismatches (`AutoFirma.js` vs `Autofirma.js`, `/usr/lib/AutoFirma` vs `/usr/lib/Autofirma`, `afirma.desktop` vs `autofirma.desktop`);
  - Windows one-profile-per-user limitation;
  - deb not calling `-uninstall`;
  - `YYYY` date format;
  - negative serials.


## 10. Restore configuration feature

"Restaurar instalación" repairs the integration between AutoFirma and the user's web browsers after installation. Typical triggers are a newly installed browser, a new OS user, or broken web signing. It (re)creates the local TLS material used by the `afirma://` WebSocket/socket channel, re-trusts the local CA in the OS and browser trust stores, re-registers the `afirma` protocol handler, and (on Windows/macOS) sets the Firefox "trust system roots" preference.

All code lives in `afirma-simple`, package `es.gob.afirma.standalone.ui.restoreconfig`. The installer-time configurator (§9) does the same job at install time. Restore is a separate, partially diverging reimplementation of it. The differences are flagged below.

### 10.1 Entry point

- Main menu, **"Herramientas"** menu (`MainMenu.32`, accessible description `"Menú con herramientas complementarias"` `MainMenu.33`), item **"Restaurar instalación"** (`MainMenu.20`).
  - Accelerator: menu-shortcut-key + `R` (Ctrl+R on Windows/Linux, Cmd+R on macOS). Mnemonic `R`. The accessible description equals the label.
  - Action: `RestoreConfigDialog.show(parentFrame, modal=true)` (`MainMenu.showRestoreConfig()`).
- The item is offered on every OS. On an OS other than Windows/Linux/macOS, the dispatcher has no implementation: it logs `"No se realizara ninguna accion"` and does nothing. Not even the start/end console lines are printed.
- The feature has no CLI or protocol entry point; it is GUI only.

### 10.2 Dialog UI (`RestoreConfigDialog`, `RestoreConfigPanel`)

Window:
- `JDialog`, modal, title `"Restaurar instalación"` (`MainMenu.20`).
- Size 600 × min(550, 0.8 × screen height) px, centred on the parent. Closing disposes it.
- Accessible description = the intro text (`RestoreConfigPanel.4`).

Layout (vertical `GridBagLayout`, from top to bottom):

1. **Intro label** (HTML, `RestoreConfigPanel.4`). Insets 15/15/11/15.
   > "Autofirma permite generar firmas electrónicas como parte de un trámite web compatible de administración electrónica. Para ello es necesario que su sistema se encuentre correctamente configurado. Si instala un nuevo navegador web, se da de alta un nuevo usuario en el sistema o tienes problemas al firmar en un trámite web, utilice esta función para restaurar la comunicación entre Autofirma y sus navegadores web."
2. **Console text area** (`taskOutput`).
   - Read-only, line-wrapped, margin 5 px. Vertical scrollbar as needed, no horizontal scrollbar. Expands to fill the remaining height.
   - Messages are appended through `appendMessage(msg)`, always on the UI thread, with a trailing platform line separator. The caret auto-scrolls to the end.
3. **Checkbox** `firefoxIntegrationCb`. **Shown only on Windows and macOS**; on Linux it exists but is never added to the UI.
   - Label: `"Configurar Firefox para que confíe en los certificados raíz del sistema."` (`RestoreConfigPanel.7`).
   - Tooltip and accessible description (`RestoreConfigPanel.8`): `"Al activarlo, se configura Firefox para que confíe en los certificados de las entidades de certificación raíz de confianza del sistema. Si no se activa, se desactivará esta opción de Firefox."`
   - Accessible name: `"Casilla de verificación para activar o desactivar "` (`RestoreConfigPanel.9`).
   - **Default: unchecked**, and it is not persisted in preferences.
4. **Buttons panel**, right-aligned (`FlowLayout.TRAILING`).
   - **"Iniciar restauración"** (`RestoreConfigPanel.1`), mnemonic `R`, accessible description `RestoreConfigPanel.2`.
   - **"Cerrar"** (`RestoreConfigPanel.5`), mnemonic `C`, accessible description `"Cierra el diálogo de restauración"` (`RestoreConfigPanel.6`).
   - Order: macOS = `[Cerrar] [Iniciar restauración]`; other OSes = `[Iniciar restauración] [Cerrar]`.

Keyboard: releasing **Escape** while the text area or a button has focus closes the dialog, except on macOS, where Escape is ignored by design.

Behaviour of "Iniciar restauración":
1. Clear the console.
2. Start `new RestoreConfigManager().restoreConfig(panel)` on a **new background thread**.
3. The button is disabled and immediately re-enabled in the same handler, so in practice it is never disabled.
   - **Quirk:** the user can start several concurrent restores.
   - "Cerrar" disposes the dialog but does not stop the worker thread, which keeps showing modal `JOptionPane`s.
   - **Recommendation:** disable both buttons while running and re-enable them on completion.

Unused leftovers (do not reimplement):
- Interface `Console`, and the `RestoreConfigPanel.3` text.
- `RestoreApplication.0..6`, `.10`.
- `RestoreConfigWindows.27`.
- `RestoreConfigMacOSX.10`, `.11`, `.14`, `.17`, `.18`.
- Resource `osx/trust_settings.plist`, which no Java code references (see §10.5).

### 10.3 Dispatcher and execution model (`RestoreConfigManager`, `RestoreConfig`)

- `RestoreConfig` is an interface with a single method, `restore(panel)`.
- `RestoreConfigManager` chooses the implementation by OS: Windows → `RestoreConfigWindows`, Linux → `RestoreConfigLinux`, macOS → `RestoreConfigMacOSX`, otherwise `null` (see §10.1).
- `restoreConfig(panel)` steps:
  1. Append `"INFO: Inicio de la restauración"` (`RestoreApplication.13`).
  2. Run `configurator.restore(panel)`.
  3. Append `"INFO: Fin de la restauración"` (`RestoreApplication.14`).
- The OS implementations catch nearly all errors and report them as console lines. Restore never fails as a whole and returns no status.
  - **Exception:** on macOS, cancelling the keychain password prompt throws `AOCancelledOperationException` out of `restore()`. That kills the worker thread and the "Fin" line is never printed.
- Message format: every console line starts with `INFO:`, `ADVERTENCIA:` or `ERROR:`. `%0` / `%1` are positional parameters.
- Blocking prompts (Swing `JOptionPane`) are shown from the worker thread. They are:
  - "close Firefox" / "close Chrome" loops;
  - the Windows "retry install" question;
  - macOS password prompts.

### 10.4 Shared constants and generated artefacts

| Item | Value | Where |
|---|---|---|
| SSL keystore file | `autofirma.pfx` (PKCS#12) | all OS |
| CA certificate file | `Autofirma_ROOT.cer` (DER) | all OS |
| SSL certificate file | `autofirma.cer` (DER) | **macOS only** |
| Keystore password (store and key) | `654321` | all OS (`KS_PASSWORD`) |
| PKCS#12 entry alias | `SocketAutoFirma` (`ConfiguratorUtil.CERT_ALIAS`) | all OS |
| NSS nickname used with certutil | `SocketAutoFirma` (`ConfiguratorUtil.CERT_ALIAS`) | Firefox / Chrome NSS |
| Windows ROOT store alias (friendly name) | `Autofirma ROOT` (`RestoreConfigUtil.CERT_ALIAS_BROWSER`) | Windows |
| macOS keychain lookup CNs | `127.0.0.1` (SSL), `Autofirma ROOT` (CA) | macOS |
| Linux alternative dir | `$HOME/.afirma/Autofirma` | Linux |
| Windows alternative dir | `%ALLUSERSPROFILE%\Autofirma` (usually `C:\ProgramData\Autofirma`) | Windows |
| macOS working dir | `$HOME/Library/Application Support/Autofirma` | macOS (always) |
| "Application directory" | Directory that contains the running JAR (`RestoreConfigUtil.getApplicationDirectory()`) | Windows/Linux |

The PKCS#12 contains one key entry, alias `SocketAutoFirma`, holding the SSL private key and the chain `[SSL cert, CA cert]`. The CA private key is **discarded** and never written to disk.

At runtime the WebSocket server looks for `autofirma.pfx` first in the application directory, then in the alternative directory for the OS (`SecureSocketUtils.getKeyStoreFile()`). That is why restore writes to the alternative directory when the install directory is not writable.

#### 10.4.1 Certificate generation (`restoreconfig.CertUtil.getCertPackForLocalhostSsl(alias, password)`)

Provider: SpongyCastle (`"SC"`). Every generation creates a new CA.

| Field | CA certificate | SSL certificate |
|---|---|---|
| Key | RSA 2048, `SecureRandom` | RSA 2048 |
| Signature | `SHA256withRSA` (self-signed) | `SHA256withRSA`, signed by the CA key |
| Subject | `CN=Autofirma ROOT` | `CN=127.0.0.1` |
| Issuer | `CN=Autofirma ROOT` | CA subject |
| Serial | `BigInteger.valueOf(new Random().nextInt())`. 32-bit, **may be negative or zero** (quirk) | same |
| notBefore / notAfter | now / now + 10×365 days (3650 days) | same |
| SubjectKeyIdentifier | non-critical, SHA-1 of SubjectPublicKeyInfo | non-critical (JCA SKI) |
| BasicConstraints | **critical**, `cA=true`, no pathLen | non-critical, `cA=false` |
| KeyUsage | non-critical: keyCertSign, digitalSignature, keyEncipherment, dataEncipherment, cRLSign | *(absent)* |
| ExtendedKeyUsage | non-critical: serverAuth, clientAuth, anyExtendedKeyUsage | *(absent)* |
| AuthorityKeyIdentifier | *(absent)* | non-critical, from the CA public key |
| SubjectAltName | *(absent)* | non-critical: **iPAddress 127.0.0.1 only** |

**Difference vs the installer configurator** (`afirma-ui-simple-configurator` `CertUtil`, §9):

| Aspect | Restore (`afirma-simple`) | Configurator |
|---|---|---|
| SAN of SSL cert | `IP:127.0.0.1` only | `IP:127.0.0.1`, `DNS:127.0.0.1` (quirk: the IP is also added as a dNSName), `DNS:localhost` |
| CA DN constant | `"CN=" + "Autofirma ROOT"` | `ROOT_CERTIFICATE_PRINCIPAL = "CN=Autofirma ROOT"` |

Key size, algorithms, validity, extensions, password and alias are identical. A restore-generated certificate therefore lacks `DNS:localhost`. A browser connecting to `wss://localhost:…` would reject it; connections to `127.0.0.1` are fine.

**Recommendation:** use the configurator profile (§9) for both paths.

**Reuse logic:** restore never checks expiry, key match or validity of existing files. "Exists" means "reuse".

### 10.5 Embedded resources used by restore

| Classpath resource | Contents | Used by |
|---|---|---|
| `/windows/certutil.windows.zip` | Folder `certutil/` holding NSS 3.12-era (2010) Windows binaries: `certutil.exe`, `freebl3.dll`, `libnspr4.dll`, `libplc4.dll`, `libplds4.dll`, `nss3.dll`, `nssckbi.dll`, `nssdbm3.dll`, `nssutil3.dll`, `smime3.dll`, `softokn3.dll`, `sqlite3.dll`, `ssl3.dll` and the `.chk` files | Windows Firefox step. Extracted to `<workingDir>\certutil\` and deleted afterwards. |
| `/linux/certutil.linux.zip` | `certutil/certutil` plus NSS `.so` / `.a` files (2010) | Linux: extracted to `<workingDir>/certutil/` but **never used**. Linux runs the system `certutil` from `PATH` (package `libnss3-tools` / `nss-tools`). Not deleted afterwards. |
| `/osx/certutil.osx.zip` | `certutil/certutil` and the `lib*.dylib` NSS libraries (2010) | macOS Firefox step. Extracted to `~/Library/Application Support/Autofirma/certutil/`, made executable, never deleted. |
| `/windows/afirma_register.bat` | Protocol registration batch (§10.6.5) | Windows fallback when the registry write fails |
| `/windows/execute.bat` | Hybrid batch/JScript UAC elevator (§10.6.5) | Windows fallback |
| `/osx/trust_settings.plist` | Template trust-settings plist (placeholders `%SSL_SHA1%`, `%SSL_SERIALNUMBER%`, `%CA_SHA1%`, `%CA_SERIALNUMBER%`, issuer `CN=AutoFirma ROOT`) | **Not used.** Legacy, ignore. |
| `/linux/autofirma.js` | Firefox protocol prefs | **Does not exist in the source tree.** See §10.7.4. |

Zip extraction (all OSes) guards against path traversal. Each entry's canonical path must lie inside the output directory, otherwise an `IOException` is thrown ("…ruta que apuntaba fuera del directorio de destino"). Extraction is skipped if `<dir>/certutil` already exists.

### 10.6 Windows procedure (`RestoreConfigWindows`)

#### 10.6.1 Step by step

1. `appDir` = directory of the running JAR. Append `"INFO: Directorio de aplicación: %0"` (`RestoreConfigWindows.3`).
2. `firefoxSecurityRoots` = checkbox state.
3. Choose the working directory:
   - `workingDirectory = appDir` if `appDir` is writable.
   - Otherwise `%ALLUSERSPROFILE%\Autofirma`, with `usingAlternativeDirectory = true`. It is created if missing; a failure is only logged.
4. `needRebuildCerts` = NOT (`appDir\Autofirma_ROOT.cer` is a file AND `appDir\autofirma.pfx` is a file).
5. If `needRebuildCerts`:
   - Append `"INFO: Se crearán nuevos certificados SSL."` (`.38`).
   - Run `rebuildCertificates(workingDirectory)` (§10.6.2).
   - On exception, append `.33` (`"ERROR: No se han podido generar y copiar a disco los certificados SSL para la conexión con los navegadores. Se omite su configuración."`). `sslRoot = null`.
6. Else:
   - Append `"INFO: Se reutilizarán los certificados del directorio de instalación."` (`.39`).
   - If `workingDirectory ≠ appDir`, copy `autofirma.pfx` and `Autofirma_ROOT.cer` from `appDir` to `workingDirectory` (replace existing, grant all permissions).
   - Load `workingDirectory\Autofirma_ROOT.cer` (X.509, DER or PEM accepted).
   - On failure, append `.4` (`"ERROR: No se cargar el certificado raiz del directorio de instalacion."`). `sslRoot = null`.
7. If `sslRoot ≠ null`:
   - Append `"INFO: Instalando certificados SSL en el almacén de Windows..."` (`.18`).
   - Run **installRootCAWindowsKeystore** (§10.6.3).
8. If `sslRoot ≠ null`:
   - Append `"INFO: Instalando el certificado SSL en el almacén de Mozilla Firefox"` (`.13`).
   - Run **installRootCAMozillaKeystore** (§10.6.4).
9. Copy to the alternative directory. This applies only if `usingAlternativeDirectory == false` AND `%ALLUSERSPROFILE%\Autofirma` already exists:
   - Append `"INFO: Copiando el almacen SSL para la conexión con Autofirma WebStart..."` (`.36`).
   - Copy both files from `workingDirectory` into it.
   - On failure, append `.37` (ADVERTENCIA).
10. Append `"INFO: Restaurando la configuración del protocolo afirma en el registro de Windows..."` (`.24`). Run **restoreProtocolRegistry** (§10.6.5). On failure, append `.25` (`"ERROR: No se ha podido restaurar el protocolo "afirma". Ejecute Autofirma con privilegios de administrador para realizar esta tarea."`).
11. Firefox enterprise roots:
    - Append `.41` if checked (`"INFO: Configuramos Firefox para que confíe en los certificados raíz del almacén de confianza del sistema."`), else `.42` (`"INFO: Se restaura la configuración de Firefox para que sólo confíe en los certificados de su almacén."`).
    - Run `RestoreConfigFirefox.configureUseSystemTrustStore(checked)` (§10.9.4).
    - No profiles → `.44` (INFO). Other error → `.43` (ERROR).
    - **Gotcha:** the checkbox defaults to unchecked, so a default run **writes `security.enterprise_roots.enabled=false`** into every Firefox profile of every user.

#### 10.6.2 `rebuildCertificates(dir)` (dir = workingDirectory)

- **Case A: `dir\autofirma.pfx` missing.**
  1. Append `.16` (`"INFO: Eliminando los certificados SSL anteriores..."`). Delete `dir\autofirma.pfx` and `dir\Autofirma_ROOT.cer` if present; on failure append `.17` (ERROR) and continue.
  2. Append `.5` (`"INFO: Generando certificados para la comunicación con el navegador web..."`). Generate the CertPack (§10.4.1) with alias `SocketAutoFirma` and password `654321`.
  3. Append `.11` (`"INFO: Guardando en disco los certificados SSL..."`). Write `dir\autofirma.pfx` (PKCS#12 bytes) and `dir\Autofirma_ROOT.cer` (DER).
  4. If writing fails, retry both files in `%ALLUSERSPROFILE%\Autofirma`, creating it if needed. If that fails too, throw.
- **Case B: pfx present, `Autofirma_ROOT.cer` missing.**
  1. Open the PKCS#12 with `654321` and take the chain of alias `SocketAutoFirma`. The CA is the **last** element.
  2. Append `.11` and write the CA as `dir\Autofirma_ROOT.cer`.
  3. On failure, fall back to the alternative directory. **Bug:** the fallback writes the bytes to the *directory path itself*, so it always fails.
- **Case C: both present.** Append `.14` (`"INFO: Se utilizaran los certificados del directorio de instalación"`) and load the existing CA.

Returns `(certificate, file)`.

#### 10.6.3 Windows ROOT store (`installRootCAWindowsKeystore`)

The target is the **current user's** "Trusted Root Certification Authorities" store. Java opens it as `KeyStore.getInstance("Windows-ROOT")` (SunMSCAPI = `CERT_SYSTEM_STORE_CURRENT_USER`, store name `ROOT`).

1. If the store cannot be opened, append `.20` (`"ERROR: No se ha importado el certificado raíz CA "Autofirma ROOT" en almacén de Windows. …"`) and return.
2. If the entry with alias `Autofirma ROOT` equals the CA certificate (byte equality), append `.26` (`"INFO: El certificado raíz ya se encontraba instalado en el almacén de Windows."`) and return.
3. Append `.22` (`"INFO: Eliminando certificados anteriores del almacén de Windows..."`).
4. While an entry with alias `Autofirma ROOT` exists:
   - Append `.35` (`"INFO: Eliminando certificado anterior del almacén de Windows. Compruebe si se ha abierto un diálogo en segundo plano pidiendo confirmación..."`).
   - Delete the entry. Windows shows its own confirmation dialog for every deletion from the user ROOT store.
   - On error, append `.34` (ADVERTENCIA).
5. Add the CA with alias/friendly name `Autofirma ROOT`. Windows shows its own "install this root certificate?" security warning.
   - If the add fails, show a confirm dialog: title `"Error"` (`.1`), text `.0` (`"El certificado de confianza para la comunicación entre el su navegador Web y Autofirma no ha podido instalarse. … ¿Desea reintentar instalar este certificado?"`), buttons OK/Cancel.
   - OK retries the add (loop). Cancel appends `.32` (`"ERROR: Se ha cancelado la instalación del certificado en el almacén de Windows."`) and returns.

Rust note: use `CertOpenStore(CERT_STORE_PROV_SYSTEM, CERT_SYSTEM_STORE_CURRENT_USER, "ROOT")`.
- Find existing certificates by friendly name or subject CN `Autofirma ROOT`.
- Delete with `CertDeleteCertificateFromStore`.
- Add with `CertAddEncodedCertificateToStore(..., CERT_STORE_ADD_REPLACE_EXISTING)` and set `CERT_FRIENDLY_NAME_PROP_ID = "Autofirma ROOT"`.

#### 10.6.4 Firefox on Windows (`installRootCAMozillaKeystore`)

1. **Close Firefox loop** (`closeFirefox`).
   - Running check: the output of `%windir%\system32\tasklist.exe` contains `firefox.exe`.
   - If running, show a warning: title `"Aviso"` (`RestoreApplication.9`), text `"Cierre el navegador Mozilla Firefox para poder instalar el certificado de confianza de Autofirma en el navegador."` (`RestoreApplication.7`).
   - While still running and the user presses OK, show an OK/Cancel confirm with text `RestoreApplication.12` (`"No se ha cerrado el navegador Firefox. Cierre el Firefox y pulse el botón OK … Si no necesita utilizar Autofirma desde Firefox, pulse el botón Cancelar para continuar con la restauración."`).
   - If the user cancels, append `RestoreConfigWindows.45` (`"ADVERTENCIA: No se ha cerrado Firefox. Es posible que no pueda ejecutar Autofirma en todos los despliegues desde este navegador."`) and **continue anyway**.
2. Extract `certutil.windows.zip` into `<workingDir>\` (creates `<workingDir>\certutil\certutil.exe`) unless `certutil\` already exists.
3. **Uninstall the old certificate** from every user's Firefox profiles, ignoring errors:
   - User dirs = every sub-directory of the parent of `user.home` (normally `C:\Users\`), **skipping `Default`** (case-insensitive). On Windows XP the base is `C:\Documents and Settings\` and the ini path is `\Application Data\Mozilla\Firefox\profiles.ini`.
   - For each user with `<user>\AppData\Roaming\Mozilla\Firefox\profiles.ini`:
     - Resolve the user's *current* profile with the shared Firefox profile-selection algorithm (`MozillaKeyStoreUtilities.getMozillaUserProfileDirectoryWindows` / `NSPreferences`). Its order is: (1) active (locked) profile for profiles.ini v1, or the `[InstallXXXX] Default=` / state default for v2+; (2) a profile flagged `Default=1`; (3) the most recently modified profile; (4) the first profile. Profiles with fewer than 10 files are skipped as dummies. The result is converted to an 8.3 short path with forward slashes.
     - Take the profile's **parent** directory (normally `…\Firefox\Profiles`).
     - For **every sub-directory** of it, run `"<certutil.exe>" -D -d "sql:<profileDir>" -n "SocketAutoFirma"`.
4. **Install** into every user's Firefox profiles.
   - Same user enumeration, same "parent of the resolved profile → every sub-directory" expansion.
   - Per profile: `<certutil.exe> -A -d sql:<profileDir> -i <Autofirma_ROOT.cer> -n "SocketAutoFirma" -t "C,,"`. Paths are double-quoted when they contain spaces.
   - Per-user failures are logged only.
5. Delete `<workingDir>\certutil\` recursively.

Errors:
- `IOException` / `KeyStoreException`, e.g. certutil missing: append `.31` (`"ERROR: No se ha podido instalar el certificado de confianza en el almacén de Firefox."`).
- No profiles at all (`MozillaProfileNotFoundException`): append `.12` (`"INFO: No se han detectado perfiles de Mozilla Firefox en el que instalar el certificado"`).

certutil execution rules on Windows (`execCommand`):
- 5000 ms timeout; the process is killed after it.
- **Any** text on stdout or stderr counts as failure (certutil prints nothing on success).
- At most 256 lines × 1024 characters are read.

Profiles stored outside the default `Profiles` folder (custom `IsRelative=0` paths) are not covered.

#### 10.6.5 Protocol handler registration (`restoreProtocolRegistry`)

Primary path, in-process registry writes to **HKEY_CLASSES_ROOT** (JNA `Advapi32Util`). Keys are created if absent and values are always overwritten:

| Key | Value name | Data |
|---|---|---|
| `HKCR\afirma` | (Default) | `URL:Afirma Protocol` |
| `HKCR\afirma` | `URL Protocol` | `` (empty string) |
| `HKCR\afirma\DefaultIcon` | (Default) | `<appDir>\ic_firmar.ico` |
| `HKCR\afirma\shell\open\command` | (Default) | `<appDir>\Autofirma.exe %1` (**quirk:** neither the path nor `%1` is quoted) |

Writing to HKCR normally needs administrator rights, because the existing key lives in `HKLM\Software\Classes`. On any exception or error, the fallback runs `restoreProtocolRegistryByApp(appDir, workingDir)`:

1. Copy resource `afirma_register.bat` to `<workingDir>\afirma_register.bat` (all permissions). It contains:
   ```bat
   REM Registro del esquema afirma
   REG QUERY HKCR\afirma || REG ADD HKCR\afirma /ve /d "URL:Afirma Protocol"
   REG QUERY HKCR\afirma /v "URL Protocol" || REG ADD HKCR\afirma /v "URL Protocol" /d ""
   REG QUERY HKCR\afirma\DefaultIcon || REG ADD HKCR\afirma\DefaultIcon /ve /d "%*\ic_firmar.ico"
   REG QUERY HKCR\afirma\shell\open\command || REG ADD HKCR\afirma\shell\open\command /ve /d "%*\Autofirma.exe \"%%1\""
   ```
   It only **adds missing keys**: existing but wrong values are not corrected, and there is no `/f`.
2. Copy resource `execute.bat` to `<workingDir>\execute.bat`.
   - Replace `$$PATH_BAT$$` with the absolute bat path and `$$PATH_DIR_EXE$$` with `appDir`. Both have backslashes doubled, for JScript string syntax.
   - The script is a hybrid batch/JScript file.
     - Batch part: if `"%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"` succeeds (already admin), it runs `call "<afirma_register.bat>" "\"<appDir>\""`.
     - Otherwise it re-runs itself with `cscript //E:JScript //nologo`. The JScript part calls `Shell.Application.ShellExecute("cmd.exe", "/c <bat> <appDir>", "", "runas", 5)`, which raises a UAC prompt.
3. Run `<workingDir>\execute.bat` and wait for it. The result is its exit code.
   - **Quirk:** `ShellExecute` is asynchronous, so the exit code is 0 even if UAC is denied or the elevated bat fails.
4. Sleep 1 s, then delete both bat files.
5. Return codes: 2 if a bat could not be written; -2 if the process could not start.
6. A non-zero result throws, and the caller shows `.25`.

Rust reimplementation recommendation: write the same four values per user under `HKCU\Software\Classes\afirma`, which needs no elevation. Elevate only when the installation is machine-wide (`HKLM\Software\Classes\afirma`). Quote the command: `"<dir>\Autofirma.exe" "%1"`.

### 10.7 Linux procedure (`RestoreConfigLinux`)

#### 10.7.1 Step by step

1. `appDir` = directory of the running JAR (e.g. `/usr/lib/AutoFirma`). Append `"INFO: Directorio de aplicación: %0."` (`RestoreConfigLinux.3`).
2. `workingDir` = `appDir` if writable. Otherwise `$HOME/.afirma/Autofirma`, created if missing. If it cannot be created, append `.1` (`"ERROR: No se ha podido identificar un directorio de aplicación al que copiar los certificados. Se aborta la restauración."`) and **stop**.
3. User homes (`getSystemUsersHomes`):
   - Run `id -u`. If the output equals `"0"` (root), the list is every 6th field of `/etc/passwd` (`cut -d: -f6 /etc/passwd`) that contains `home/` (case-insensitive), deduplicated. Otherwise the list is just `user.home`.
   - **Bug:** the output `"0\n"` is compared to `"0"` without trimming, so root detection always fails. In practice **only the current user's home is processed**, even when run as root.
   - On failure, append `.6` (ERROR) and skip the certificate step.
4. If the homes list is available, run **restoreSslCertificates** (§10.7.2).
5. Append `.15` (`"INFO: Restaurando la configuración del protocolo "afirma" en Mozilla Firefox... (Puede que se le soliciten permisos de administrador)"`). Run **restoreProtocolHandler** (§10.7.4). On failure, append `.16` (`"ERROR: No se ha podido restaurar la configuración del protocolo "afirma"."`).

#### 10.7.2 `restoreSslCertificates(appDir, workingDir, homes)`

1. **pfx missing in `appDir`.**
   - Append `.5` (`"INFO: Generando certificado para la comunicación con el navegador web..."`).
   - Delete `appDir/autofirma.pfx` and `appDir/Autofirma_ROOT.cer` if present; a failure is only logged.
   - Generate a CertPack (§10.4.1). On error, append `.2` (ERROR) and return.
   - Append `.11` (`"INFO: Guardando almacén de claves..."`). Write `workingDir/autofirma.pfx` and `workingDir/Autofirma_ROOT.cer`. On error, append `.4` (`"ERROR: No se han podido copiar los certificados de confianza SSL a disco."`) and return.
2. **pfx present, CA missing in `appDir`.** Load the pfx (`654321`), take the chain of the **first alias**, and write the last element to `workingDir/Autofirma_ROOT.cer`. On error, append `.4` and return.
3. **Both present.** `rootCertFile = appDir/Autofirma_ROOT.cer`. Append `.14` (`"INFO: El certificado para la configuración del canal seguro ya se encuentra generado."`).
4. Extract `certutil.linux.zip` into `workingDir/certutil/` (unused, see §10.5). On error, append `.17` (ERROR) and return.
5. **Chrome/Chromium NSS.**
   - Append `.9` (`"INFO: Instalando el certificado en el almacén del sistema..."`). Despite the wording this is only the user NSS DB, not the system CA bundle.
   - Close-Chrome loop: the running check looks for `/opt/google/chrome/chrome` in `/bin/bash -c "ps -aux"`. Warning `RestoreApplication.8` (`"Cierre el navegador Chrome para registrar el protocolo de Autofirma en el navegador."`), then an OK/Cancel loop with `RestoreApplication.11`. Cancel continues.
   - For each home and each sub-path in [`/.pki/nssdb`, `/snap/chromium/current/.pki/nssdb`] that **exists as a directory**: run certutil through the script mechanism (§10.9.2) with `certutil -d sql:<home><subpath> -A -n "SocketAutoFirma" -i <Autofirma_ROOT.cer> -t "TCP,TCP,TCP"`.
   - On exception, append `.10` (ERROR).
6. **Firefox.**
   - Append `.13` (`"INFO: Instalando el certificado de confianza SSL en el almacén de Mozilla Firefox..."`).
   - Close-Firefox loop: the running check looks for `/usr/lib/firefox/firefox` in `ps -aux`, so snap and flatpak Firefox are not detected. Same dialogs as Windows; if not closed, append `RestoreConfigWindows.45`.
   - Pre-uninstall: calls the Windows-oriented `uninstallRootCAMozillaKeyStore`. On Linux it fails internally (the users base path is null) and is silently ignored. The per-profile uninstall script below removes old entries anyway.
   - Install (§10.9.1 Linux discovery). Per profile: `certutil -A -d sql:<profile> -i <Autofirma_ROOT.cer> -n "SocketAutoFirma" -t "C,,"`.
   - No profiles: append `.12` (`"ADVERTENCIA: No se ha detectado un perfil de Mozilla Firefox en el que instalar el certificado."`). Other error: append `.18` (ADVERTENCIA).

Unlike the configurator (§9), Linux restore does **not** honour flatpak Firefox (`~/.var/app/org.mozilla.firefox/...`) or flatpak Chromium/Chrome NSS DBs.

#### 10.7.3 Privileges

The certificate operations run as the invoking user, with no elevation. Only the Firefox protocol-preference copy uses `pkexec`.

#### 10.7.4 Firefox protocol handler (`restoreProtocolHandler(workingDir)`)

1. Read classpath resource `/linux/autofirma.js`.
   - **Gotcha:** this resource does **not exist** in `afirma-simple`. The installer ships `AutoFirma.js` instead (§9). So this step always fails and prints `.16`.
   - Intended content, the same as the installer file `/etc/firefox/pref/AutoFirma.js` and `/usr/lib/firefox/defaults/pref/AutoFirma.js`:
     ```js
     pref("network.protocol-handler.expose.afirma",false);
     pref("network.protocol-handler.external.afirma",true);
     pref("network.protocol-handler.warn-external.afirma",false);
     pref("network.protocol-handler.app.afirma","/usr/bin/autofirma");
     ```
2. Write it to `<workingDir>/autofirma.js`.
3. Candidate Firefox pref directories:
   - for each entry `P` of `java.library.path` (split on `:`), `P/firefox/defaults/pref` (e.g. `/usr/lib/firefox/defaults/pref`, `/usr/lib64/firefox/defaults/pref`);
   - plus `/etc/firefox/pref`.
   - Only directories that exist are kept.
4. Write `<workingDir>/restoreprotocol.sh`:
   ```sh
   #!/bin/sh
   cp -f "<workingDir>/autofirma.js" "<prefDir>/autofirma.js"     # one line per existing prefDir
   rm "<workingDir>/autofirma.js"
   ```
5. Run `chmod 755 <script>`, then `pkexec <script>` (polkit admin prompt) and wait. A non-zero exit throws, with stderr logged.
6. `rm <script>`.

The restore **writes `autofirma.js` in lower case**, while the installer uses `AutoFirma.js`. Both files can coexist. Restore does **not** touch `xdg-mime`, `.desktop` files, `x-scheme-handler/afirma`, `update-desktop-database`, Chrome policies or `/etc/opt/chrome/policies`.

Dead code: `RestoreConfigFirefox.removeAppExecutionWarningInChrome` / `createScriptsRemoveExecutionWarningInChrome`.
- Intent: generate `sed` scripts that inject `"afirma":false,` into `"protocol_handler":{"excluded_schemes":{` in `~/.config/google-chrome/Local State` and `~/.config/chromium/Local State`.
- It is never called and the scripts are never executed. Do not reimplement; use Chrome policies instead (§9).

### 10.8 macOS procedure (`RestoreConfigMacOSX`, `RestoreConfigFirefoxMacOS`)

#### 10.8.1 Step by step

1. `userDirs = [$HOME]`. Only the current user is processed, because of permissions.
2. `firefoxSecurityRoots` = checkbox state.
3. `appDir = $HOME/Library/Application Support/Autofirma`. This is never the `.app` bundle; it is the same directory the configurator uses (§9). Append `"INFO: Directorio de aplicación: %0 "` (`RestoreConfigMacOSX.3`).
   - If missing, create it with POSIX perms `rwxrwxr-x` (fallback: plain `mkdirs`).
   - If it still does not exist, append `.1` (`"ERROR: No se tienen permisos sobre el directorio de aplicacion. Concédalos manualmente repita la restauración."`) and **stop**.
4. Create a temp script file `$TMPDIR/installCerScript<random>.sh` with mode 0777. On failure, append `.15` (ERROR) and **stop**.
5. **Change ownership.** Append `chown <$USER> "<appDir>"` to the script and run it **as administrator**:
   - command: `/usr/bin/osascript -e 'do shell script "<script path>" with administrator privileges'`;
   - this raises the macOS GUI admin authentication prompt;
   - errors are only logged.
6. **Prepare the certificate files** in `appDir`: `Autofirma_ROOT.cer`, `autofirma.cer`, `autofirma.pfx`.
   - If `autofirma.pfx` is missing:
     - Append `.5`.
     - Generate a CertPack (§10.4.1).
     - Delete, then write, `Autofirma_ROOT.cer` (CA, DER), `autofirma.pfx` and `autofirma.cer` (SSL cert, DER).
     - Errors: IO → `.7` (ERROR), crypto → `.9` (ERROR). In both cases skip all certificate steps.
   - Else:
     - Load the pfx (`654321`) and take the chain of the first alias.
     - Overwrite `Autofirma_ROOT.cer` with `chain[last]` and `autofirma.cer` with `chain[0]`.
     - Error → `RestoreConfigLinux.4` and skip the certificate steps.
7. **Keychain** (§10.8.2), only if the files are ready.
8. **Firefox** (§10.9.1 macOS discovery). Runs only if at least one profile exists:
   - Append `.21` / `.22` (same texts as Windows `.41` / `.42`) and run `configureUseSystemTrustStore(checked)` per profile.
     - Each profile appends `"INFO: Editamos la confianza de Firefox en el almacén del sistema para el perfil: %0"` (`.38`).
     - Each failure appends `.39` (ADVERTENCIA).
     - No profiles → `.24`. Other error → `.23`.
     - If `user.js` is not writable and not owned by `$USER`, run `chown -f $USER <user.js>` as administrator through osascript first.
     - **Gotcha:** an unchecked box writes `false`.
   - If the certificate files are ready:
     - Run the close-Firefox loop: `ps aux` output contains `Firefox.app`, `FirefoxNightly.app` or `FirefoxDeveloperEdition.app`. Same dialogs; if not closed, append `RestoreConfigWindows.45`.
     - Append `.13` (`"INFO: Instalando el certificado en el almacén de Mozilla Firefox..."`) and run the reinstall (§10.8.3).
9. Delete the temp script. On failure, log and return.

#### 10.8.2 Keychain (`restoreSslCertificatesInKeyChain`)

1. **Obtain the password** (`getKeyChainPhrase(force=false)`).
   - First try the literal `dummy`: run `security unlock-keychain -p dummy`, which targets the default keychain.
   - Exit 0 → use `dummy`.
   - Non-zero with stderr containing `password` (ignoring a leading `Password:`) → prompt the user with a password dialog:
     - text `"Inserte la contraseña del administrador para la importación de los certificados"` (`.29`);
     - after a wrong password, `"Contraseña incorrecta. Inserte la contraseña …"` (`.30`).
     - The entered password is verified with `security unlock-keychain -p <pwd>`.
   - Cancelling the password dialog shows a Yes/No confirm: title `"Cancelar importacion"` (`.32`), text `.31` (`"Si cancela la importación de los certificados no podrá utilizar Autofirma desde el navegador del sistema. ¿Desea cancelar la instalacion?"`).
     - Yes → append `.33` and abort the whole restore (uncaught cancellation, see §10.3).
     - No → prompt again.
   - Any other error → continue with `dummy`.
   - **The same secret is then fed to `sudo -S`**, so it must be both the login-keychain password and an admin (sudoer) password.
2. **Remove previous certificates.** For each CN in [`127.0.0.1`, `Autofirma ROOT`], repeat:
   1. Run `sudo -S security find-certificate -c <CN> -Z`, writing the password to stdin.
   2. Exit 0: parse the text after the first `hash:` up to end of line. This is the first hash printed, SHA-256 on modern macOS.
   3. Run `sudo -S security delete-certificate -Z <hash> -t`. No password is written here; it relies on sudo's timestamp cache. `-t` also removes trust settings.
   4. Stop when `find-certificate` fails with stderr containing `SecKeychainSearchCopyNext`.
   - stderr containing `password` → invalid password → re-prompt (`force=true`) and redo the whole removal.
   - Other errors are logged.
   - **Quirk:** if `find-certificate` succeeds but no `hash:` is parsed, the loop never ends.
3. Append `"INFO: Importando certificado en el almacén de confianza del sistema..."` (`.6`).
4. **Install the trusted certificates** into the **System keychain**. stdin = password.
   - CA: `sudo -S security -i add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <appDir>/Autofirma_ROOT.cer`, then append `"INFO: Certificado de CA importado."` (`.25`).
   - SSL: `sudo -S security -i add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain <appDir>/autofirma.cer`, then append `"INFO: Certificado SSL importado."` (`.26`).
   - (`-i` puts `security` in interactive mode. It is an artefact; reimplement without `-i`.)
   - On any failure:
     - append `.20` (`"ERROR: No se ha podido instalar el certificado de confianza SSL en el llavero del sistema."`);
     - show an error dialog titled `"Error en la importación"` (`.28`) with `.27`, an HTML list of the two file paths the user must install manually.

Rust recommendation: use the Security framework (`SecTrustSettingsSetTrustSettings` in the admin domain via an authorized helper). Alternatively, invoke `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain` through a single `osascript … with administrator privileges` call, which avoids handling the password in-process.

#### 10.8.3 Firefox NSS on macOS (`reinstallRootCAMozillaKeyStore`)

1. Extract `/osx/certutil.osx.zip` into `appDir` (→ `appDir/certutil/certutil` and the dylibs) if `appDir/certutil` does not exist. `chmod 777` every file in it.
2. For each profile directory:
   1. Append `"INFO: Restauramos los certificados en el perfil de Firefox: %0"` (`.36`, profile folder name).
   2. **Overwrite** the temp script with the following. `<cu>` is the certutil path and `<db>` is `sql:<profile>` if `<profile>/pkcs11.txt` exists, else `<profile>`. Spaces in paths are escaped as `\ `:
      ```sh
      export PATH=$PATH:<certutilDir>
      export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<certutilDir>
      max=$(<cu> -L -d <db> | grep Autofirma | wc -l);for ((i=0; i<$max; i++));do <cu> -D -d <db> -n "SocketAutoFirma";done
      <cu> -A -d sql:<profile> -i <appDir>/Autofirma_ROOT.cer -n "SocketAutoFirma" -t "C,,"
      ```
   3. Run it **without** admin rights: `osascript -e 'do shell script "<script>"'`.
   4. A non-zero exit appends `.37` (`"ADVERTENCIA: No se ha pudieron restaurar los certificados en el perfil '%0'. Es posible que el usuario no posea permisos sobre el mismo."`).
3. Any profile error throws, and the caller appends `.19` (ADVERTENCIA). If certutil is missing or not executable: `.35`. No profiles: `.12`.

Quirks:
- `grep Autofirma` is case-sensitive, so it does **not** match the nickname `SocketAutoFirma`. The delete loop normally runs zero times, and `-A` just adds or updates.
- `LD_LIBRARY_PATH` is irrelevant on macOS; the bundled dylibs resolve via `@executable_path`.
- The error flag reflects only the **last** profile.

### 10.9 Shared Firefox / NSS helpers (`RestoreConfigFirefox`)

#### 10.9.1 Profile discovery

| OS | profiles.ini searched | Profile dirs taken |
|---|---|---|
| Windows (install/uninstall) | `<each C:\Users\* except Default>\AppData\Roaming\Mozilla\Firefox\profiles.ini` | Parent of the *selected* profile (selection algorithm in §10.6.4), then **every** sub-directory of it |
| Windows (`user.js` enterprise roots) | `<each C:\Users\*, including Default>\AppData\Roaming\Mozilla\Firefox\profiles.ini` | Every `Path=` line, resolved relative to the ini's directory, if it is an existing directory |
| Linux | For each home: `<home>/snap/firefox/common/.mozilla/firefox/profiles.ini` and `<home>/.mozilla/firefox/profiles.ini` | Every `Path=` line, resolved relative to the ini's directory, if it is an existing directory |
| macOS | `$HOME/Library/Application Support/firefox/profiles.ini` (lower-case `firefox`; only works on case-insensitive volumes) | Every `Path=` line relative to the ini directory, if it is a directory |

`Path=` parsing:
- Lines are read with a bounded reader: at most 256 lines of at most 2048 characters each.
- `IsRelative=0` (absolute `Path=`) is **not** handled. The value is concatenated to the ini directory, so absolute-path profiles are silently skipped.
- A reimplementation should honour `IsRelative`.

#### 10.9.2 certutil invocation on Linux (`execCommandLineCertUtil`)

- The binary is `certutil` from `PATH`.
- For each call, write two scripts in `workingDir`: `installRestore-<randInt>.sh` (the install command) and `uninstallRestore-<randInt>.sh` (the matching delete).
  - Firefox delete: `certutil -D -d sql:<profile> -n "SocketAutoFirma"`.
  - Chrome delete: `certutil -D -d sql:<nssdb> -n "SocketAutoFirma"`.
  - Neither script has a shebang.
- `chmod 0777` both. Run the uninstall script (ignore its result), then the install script. There is no timeout.
- Failure = any output on stdout/stderr. Delete both scripts afterwards.
- Only **one** instance of a duplicated nickname is removed per run.
- Spaces in paths are escaped with `\ `.

#### 10.9.3 certutil trust flags

- Firefox profiles: `-t "C,,"` (trusted CA for SSL only).
- Linux Chrome/Chromium user NSS DB: `-t "TCP,TCP,TCP"`.
- Nickname: always `SocketAutoFirma`.

#### 10.9.4 `user.js` edit, enterprise roots (Windows and macOS only)

Preference: `security.enterprise_roots.enabled`. Line format: `user_pref("security.enterprise_roots.enabled", true|false);` followed by CRLF.

- **Existing `<profile>/user.js`:**
  1. Read the lines (platform charset).
  2. Replace every line that *contains* `security.enterprise_roots.enabled` with the new pref line. Keep other lines, re-terminated with `\r\n`.
  3. If the pref was not found, append `"\r\n// Confianza en los certificados raices del almacen del sistema\r\n"` followed by the pref line.
  4. Rewrite the file as UTF-8.
- **Missing `user.js`:** create it with `"// === PROPIEDADES PERSONALIZADAS DE CONFIGURACION ===\r\n"`, then `"\r\n// Confianza en los certificados raices del almacen del sistema\r\n"`, then the pref line.
- No profiles → `MozillaProfileNotFoundException`.

The original never writes Firefox `policies.json` and never uses `ImportEnterpriseRoots`.

### 10.10 What restore does NOT do

- It does not check certificate **expiry** or pfx/cer consistency. Existing files are reused even if they are expired or mismatched. The only way to force regeneration is to delete `autofirma.pfx`.
- **Windows:**
  - No Chrome/Edge policies, no `HKCU\Software\Classes` registration, no file associations, no context menus.
  - No Firefox protocol prefs.
  - No machine-wide `LocalMachine\ROOT` store; only the current user's ROOT.
- **Linux:**
  - No system CA bundle (`update-ca-certificates`, `trust anchor`), no `xdg-mime`/`.desktop`/`mimeapps.list` registration, no Chrome/Chromium policies.
  - No flatpak paths, and no enterprise-roots checkbox.
  - The protocol step is broken (missing resource).
- **macOS:**
  - No LaunchServices / `lsregister` re-registration of the `afirma` URL scheme, and no Chrome policies.
  - Only the current user.
- It does not touch AutoFirma's own preferences (§4), plugins (§7) or the trusted-certificates/secure-domains lists.
- It produces no log file of its own beyond the general application log (§1).

### 10.11 Reimplementation notes

1. Run the restore off the UI thread. Lock the "start" button, and make cancellation and close behaviour explicit.
2. Share **one** certificate-generation routine with the configurator (§9). Use the SAN set `IP:127.0.0.1`, `DNS:localhost`, a positive random serial (≥64 bits), and keep alias `SocketAutoFirma` with password `654321` for compatibility. Optionally regenerate when the existing certificates are expired or close to expiry.
3. Keep the file names (`autofirma.pfx`, `Autofirma_ROOT.cer`, macOS `autofirma.cer`) and the lookup order: application dir, then OS alternative dir (`%ALLUSERSPROFILE%\Autofirma`, `~/.afirma/Autofirma`, `~/Library/Application Support/Autofirma`).
4. Prefer native NSS / CryptoAPI / Security framework calls over bundled 2010-era certutil binaries. If certutil is kept, treat a non-zero exit code as failure, rather than "any output". Remove *all* entries with the nickname `SocketAutoFirma`.
5. Make the enterprise-roots checkbox **tri-state or default to "leave unchanged"**, so that restore does not silently disable `security.enterprise_roots.enabled`.
6. Fix the Linux protocol step: ship the pref content from §10.7.4, and also re-run the installer's desktop/mime registration (§9).
7. Profile discovery should honour `IsRelative`, snap and flatpak paths, and every user when elevated.



## 11. Internationalisation

### 11.1 Supported languages

Built-in locales (`LanguageManager.AFIRMA_DEFAULT_LOCALES`, same list duplicated in `afirma-keystores-jmulticard-ui/LanguageUtils`), in menu order:

| Locale id | Language | Menu label (endonym, identical in every bundle) | Message key |
|---|---|---|---|
| `es_ES` | Spanish (default and ultimate fallback) | `Español` | `MainMenu.39` |
| `ca_ES` | Catalan | `Catalá` (sic, should be "Català") | `MainMenu.41` |
| `gl_ES` | Galician | `Galego` | `MainMenu.42` |
| `eu_ES` | Basque | `Euskera` | `MainMenu.43` |
| `va_ES` | Valencian (non-ISO language code `va`) | `Valencià` | `MainMenu.44` |
| `en_US` | English | `English` | `MainMenu.40` |

Rust note: `va` is not a valid ISO 639-1 code; keep `va_ES` as the persisted identifier for compatibility, but map it internally to e.g. `ca-ES-valencia` for any library that validates BCP-47 tags.

### 11.2 Selecting and persisting the language

- Preference key `default.locale` (string, `<lang>_<COUNTRY>`), default `es_ES` (from `preferences.properties`). Administrators can preset it as a system preference with the configurator option `-default_language <ll_CC>` (only applied if the locale is built-in or already imported; see §9), and import a pack with `-language_path <zip>`.
- At start-up (§1.3 step 4) the GUI reads `default.locale` (empty → `es_ES`), builds the `Locale` (split on `_`: 1, 2 or 3 parts), calls `Locale.setDefault`, re-writes the preference, initialises `LanguageManager.init(<alternative dir>/languages)` and reloads `SimpleAfirmaMessages`. The CLI does the same but falls back to the OS default locale if the preference were empty (in practice it never is because of the default).
- Consequence: the OS UI language is **never** used automatically; Autofirma is in Spanish until the user picks another language. (Rust improvement: default to the OS language when it is one of the six, but keep honouring an explicit `default.locale`.)
- Menu "Idioma" (`MainMenu.38`) in the main menu bar (§2): a radio group with the six built-in languages followed by imported languages (not duplicating a built-in locale), a separator and "Importar idioma" (`MainMenu.45`, accelerator Ctrl/Cmd+I). Selecting a language: `Locale.setDefault`, store `default.locale`, reload messages, then `showRestartWarning()`:
  - if a restart command can be computed (§1.17): confirm dialog title `MainMenu.50` "Reiniciar Autofirma", text `MainMenu.51` "Es necesario reiniciar la aplicación para que los cambios surtan efecto. ¿Desea que se reinicie la aplicación?"; YES → start the new process and `System.exit(0)`; NO → keep running (only some texts change immediately).
  - else: warning `MainMenu.49` "Reinicie la aplicación para que los cambios surtan efecto." with the same title.
  - `JSEUIMessages.updateLocale()` is called so generic dialogs switch immediately.

### 11.3 Language packs (import)

"Importar idioma": file chooser titled `MainMenu.46` ("Abrir fichero para importar idioma"), filter `*.zip` described as `MainMenu.47 + " (*.zip)"` ("Archivo comprimido (*.zip)"). `LanguageManager.addLanguage(zip)`:

1. Read the ZIP entry `metadata.info` (UTF-8/platform text, `key=value` per line; a line without `=` is an error). Keys:
   - `locale` – target locale id `ll_CC` (required).
   - `language.name` – label shown in the language menu.
   - `fallback.locale` – `ll_CC` of the base locale used for missing keys.
2. Destination `<alternative dir>/languages/<locale>/` (Windows `%ALLUSERSPROFILE%\Autofirma\languages\…`, Linux `~/.afirma/Autofirma/languages/…`, macOS `~/Library/Application Support/Autofirma/languages/…`); directories are created with permissions for all users.
3. Copy the ZIP there, make it world-readable/writable, extract every entry: entries under `help/` (or `help\`) go to `<home>/.afirma/Autofirma/help/` (minus the `help/` prefix), all others into the locale directory. The copied ZIP is then deleted.
4. Errors → `AOException` code `230001` → message `LanguageManagementError.230000` (generic; see §1.18 quirk). Success → info dialog `MainMenu.52` "El idioma se ha importado correctamente", the new item is added/selected in the menu, `default.locale` is set to it, and the restart prompt is shown.

A pack can also *replace* a built-in language: if `<languages>/<es_ES|…>/` exists for the current built-in locale, the imported files take precedence (see lookup below).

Expected pack content (one UTF-8 `.properties` file per bundle, named `<basename>_<ll>_<CC>.properties`, at the ZIP root): `simpleafirmamessages`, `commandlinemessages`, `protocolmessages`, `signpdfuimessages`, `updatermessages`, `uimessages`, `certdialogmessages`, `keystoremessages`, `coremessages`, `protocolomessages`, `validationmessages`, `xadesmessages`, `xmlmessages`, `firefoxmessages`, `jmulticarduimessages`, `messages` (configurator), plus `help/index_<ll_CC>.html` and `help/<ll_CC>/…` pages.

### 11.4 Message lookup algorithm (all `*Messages` classes, e.g. `SimpleAfirmaMessages`)

```
changeLocale():
  cur = Locale.getDefault()
  if cur is built-in and no directory <languages>/<cur> exists:
       bundle = classpath bundle <BUNDLE_NAME> for cur (fallback ENGLISH bundle on error)
  else:
       bundle = PropertyResourceBundle(UTF-8 file <languages>/<ll_CC>/<basename>_<ll>_<CC>.properties)
       if missing: classpath bundle for es_ES
getString(key):
  1. bundle[key]
  2. else: base = fallback.locale from <languages>/<cur>/metadata.info;
           base built-in ? classpath bundle(base)[key] : imported file for cur [key]
  3. else: classpath es_ES bundle [key]
  4. else: log warning, return "!" + key + "!"
getString(key, p0, p1, ...): same, then replace each "%i" (i = 0..n-1) with p_i (null params skipped)
```

Formatting conventions:
- Placeholders are `%0`, `%1`, … replaced by plain `String.replace` (no `MessageFormat`, no escaping; `%10` would be corrupted by `%1` — never occurs). Exception: the configurator's `Messages` uses 1-based `%1`, `%2`… (`text.replace("%" + (i+1), params[i])`); `JSEUIMessages.getString(key, text)` replaces only `%0`.
- Many values contain HTML (`<html>…<br>…</html>`, `&oacute;` entities) rendered by Swing labels; some contain `\n` line breaks for `JOptionPane`. Rust port: convert to plain text + explicit line breaks or a minimal markup, and decode entities at build time.
- Classpath `.properties` files are ISO-8859-1 with `\uXXXX` escapes (Java 8 rule); imported files are read as UTF-8.

### 11.5 Resource bundle inventory

`afirma-simple` (`src/main/resources/properties/<name>/<name>_<ll_CC>.properties`, all six locales present):

| Bundle base name | Accessor class | Keys | Content | Locale gaps (vs es_ES) |
|---|---|---|---|---|
| `properties.simpleafirmamessages.simpleafirmamessages` | `SimpleAfirmaMessages` | 1136 | All desktop GUI texts | en_US: keys `PreferencesPanelPolicy.0-9` misspelled `PreferencePanelPolicy.*`; eu_ES: `SignDataPanel.22` misspelled `SignDataPanel`; gl_ES: `PreferencesPanel.FacturaE.27` spelled `PreferencesPanel.Facturae.27` (lookups fall back to es_ES) |
| `properties.commandlinemessages.commandlinemessages` | `CommandLineMessages` | 149 | CLI syntax/help and errors (§5) | `CommandLineLauncher.146`–`.149` only in es_ES |
| `properties.protocolmessages.protocolmessages` | `ProtocolMessages` | 100 | afirma:// protocol dialogs/errors | va_ES lacks `ProtocolLauncher.67` |
| `properties.signpdfuimessages.signpdfuimessages` | `SignPdfUiMessages` | 131 | Visible PDF signature dialogs (§3) | en_US: `SignPdfUiStamp.11/.13` misspelled `SignPdfUiStam.*` |
| `properties.updatermessages.updatermessages` | `UpdaterMessages` | 5 | Updater (§8) | — |

Other modules used by the desktop app:

| Module | Bundle base name | Locales | Notes |
|---|---|---|---|
| `afirma-ui-core-jse` | `uimessages.uimessages` (`JSEUIMessages`) | es, ca, gl, eu, va, en | 25 keys: generic dialogs, file chooser, password dialogs |
| `afirma-ui-core-jse-keystores` | `certdialogmessages.certdialogmessages` (`CertificateSelectionDialogMessages`) | all six | 55 keys; gl_ES lacks `UtilToolBar.4`. Plus `resources/selectiondialogutil.properties` (`helpUrl`) |
| `afirma-keystores-jmulticard-ui` | `properties.jmulticarduimessages.jmulticarduimessages` | all six | 22 keys: DNIe/CERES PIN and confirmation dialogs |
| `afirma-core` | `resources.coremessages.coremessages`, `resources.protocolomessages.protocolomessages` | all six | 13 / 2 keys |
| `afirma-core-keystores` | `keystoremessages.keystoremessages` | all six | 45 keys |
| `afirma-keystores-mozilla` | `firefoxmessages.firefoxmessages` | all six | 2 keys |
| `afirma-crypto-validation` | `validationmessages.validationmessages` | all six | 28 keys (validation results in the viewer) |
| `afirma-crypto-xades` | `xadesmessages.xadesmessages` | all six | 2 keys |
| `afirma-crypto-core-xml` | `xmlmessages.xmlmessages` | all six | 4 keys |
| `afirma-core-massive` | `massivesignmessages` (`MassiveSignMessages`; duplicate copy also under `massivesignmessages/`) | base (Spanish) + `gl_ES` only | 37 keys; gl lacks `DirectorySignatureHelper.23`; no lookup of imported packs. Other languages get Spanish. |
| `afirma-simple-plugin-hash` | `es.gob.afirma.plugin.hash.messages` | base (Spanish) only | 153 keys; hash plugin is Spanish-only |
| `afirma-simple-plugin-validatecerts` | `es.gob.afirma.plugin.certvalidation.messages`, `…certvalidationmessages` | base (Spanish) only | 19 / 12 keys |
| `afirma-ui-simple-configurator` | `es.gob.afirma.standalone.configurator.messages` (`Messages`) | all six | 89 keys; supports imported packs via a `URLClassLoader` over the locale directory |
| `afirma-ui-simple-configurator-common` | `es.gob.afirma.standalone.configurator.common.ConfiguratorCommonMessages` | all six | 4 keys |

Help HTML (§1.15): `help/index_<ll_CC>.html` and `help/<ll_CC>/…` for all six locales (identical page set). Installer licence texts: `afirma-simple-installer/license/licencia_{es,ca,gl,eu,va,en}.txt` (+ `licencia.txt`), macOS pkg `resources/licencia_<ll_CC>.txt`. The Windows NSIS installer is itself localized (Spanish, English, Catalan, Basque, Galician, Valencian via a custom `Valencian.nlf/.nsh`) – §9.

### 11.6 Reimplementation notes

- Use a single message catalogue per locale (e.g. Fluent or gettext) generated from the Java bundles, keeping the original keys as ids for traceability; fix the misspelled keys during conversion.
- Implement the 4-level fallback (current → pack `fallback.locale` → es_ES → `!key!`).
- Support importing the same ZIP format (`metadata.info` + `<basename>_<ll>_<CC>.properties` + `help/`), mapping old bundle names to the new catalogue.
- Allow switching language without restart if the toolkit permits; otherwise keep the restart prompt.


## 12. Accessibility

Autofirma is used by public administrations and must meet Spanish/EU accessibility requirements (UNE-EN 301 549 / WCAG-based). The Java original implements accessibility mostly through Swing conventions; there are **no accessibility-specific preferences** in the desktop app (no font-size, zoom or contrast setting). The Rust port must reach at least parity and should improve it (native accessibility APIs: UI Automation on Windows, NSAccessibility on macOS, AT-SPI on Linux).

### 12.1 High contrast and theming

- Windows high contrast is detected via the desktop property `win.highContrast.on` (`LookAndFeelManager.WINDOWS_HIGH_CONTRAST`, also `AccesibilityUtils.HIGH_CONTRAST` in the PIN dialogs, where Linux is *always* treated as high contrast).
- When high contrast (or large system font, or Linux) is detected, the native system Look&Feel is used instead of Nimbus, so system colours apply (§1.12).
- Under high contrast many panels skip setting their custom background (`DEFAULT_COLOR`/white) so OS colours show through (checked in `MainScreen`, `SignPanel`, `SignPanelFilePanel`, `SignPanelMultiFilePanel`, `SignDataPanel`, `SignDetailPanel`, `SignResultPanel`, `SignResultListPanel`, `MassiveResultProcessPanel`, `VisorPanel`, `ValidationInfoPanel`, `DocumentInfoPanel`, `SignatureConfigInfoPanel`, `DNIeWaitPanel`, `LinksTreeCellRenderer`, `SignPdfUiPanel`).
- `LookAndFeelManager.SECUNDARY_COLOR` = black under high contrast, white otherwise (secondary panel backgrounds).
- Hyperlink-style labels (`LabelLinkManager`): underlined; normal colour blue, focused = white text on blue background; under high contrast yellow text (focused and unfocused).
- HTML panes with links (`EditorFocusManager`): body font forced to the default label font family/size; under high contrast the body text colour is forced to the label foreground colour; links unfocused = underlined blue, focused = `Tree.selectionBackground`/`Tree.selectionForeground` colours.
- Dark mode: only a (broken) GNOME dark-theme detection exists (§1.12). Rust port should follow the OS light/dark/high-contrast settings natively.

### 12.2 Font size and scaling

- No in-app font size control. Large Windows system fonts (`win.defaultGUI.font.height` > 13) switch to the native L&F, which honours the system font size; on Linux GTK L&F is always used.
- `ResizingTextPanel` (DNIe wait screen texts and the "drop a file here" area of the sign panel): the text font grows/shrinks to fill the panel width (width − 3×30 px margin) whenever it repaints.
- `ScalablePane`: images (DNIe picture, file-type icons, result OK/KO icons) scale to fit their container keeping aspect ratio.
- Small screens: windows are maximised when the screen height is ≤ 600 px; Preferences, Restore-config, Plugins, Permissions and PDF dialogs size themselves relative to screen height.
- PIN/CAN dialogs (`afirma-keystores-jmulticard-ui`, `AbstractJAccessibilityCustomDialog`): resizable; on resize all fonts are scaled proportionally to the window area (`ResizingAdaptor`); they include "Restaurar" (mnemonic R) and "Maximizar" (mnemonic M) buttons. Additional modes (bold font, big font, focus highlighting, forced contrast) exist in code but are hard-wired off (`GeneralConfig` returns `false`).
- HiDPI: delegated to the JRE (Java 9+ per-monitor scaling); Metal L&F forced on three known HiDPI Windows tablets (§1.12).

### 12.3 Screen-reader support

Pattern used throughout (≈280 calls in 37 GUI classes of `afirma-simple`, plus `afirma-ui-core-jse`, `-keystores`, jmulticard UI and the hash plugin):

- Every actionable control gets `getAccessibleContext().setAccessibleName(...)` and/or `setAccessibleDescription(...)` from the message bundles (e.g. sign button, "Ver fichero" button: name `SignPanel.52` "Botón de ver fichero"; select-file button description `SignPanel.33` "Pulse este botón o arrastre un fichero al área inferior para iniciar el proceso de selección de fichero a firmar"; DNIe buttons `DNIeWaitPanel.2`/`.6`/`.5`/`.1`).
- Labels are bound to their inputs with `JLabel.setLabelFor(component)` (~60 uses: preferences fields, PDF signature text/fonts, proxy fields, etc.).
- Containers/screens get descriptive accessible descriptions so that screen readers announce the screen purpose when it appears (e.g. the main window on the DNIe screen gets `DNIeWaitPanel.3 + DNIeWaitPanel.7`; the close confirmation panel gets `SimpleAfirma.47`).
- Generic dialogs (`JSEUIManager` in `afirma-ui-core-jse`): `showMessageDialog/showConfirmDialog/showInputDialog` copy the accessible description of the message component (or the message string) to the dialog; OK/Cancel buttons of password dialogs get descriptions; the file chooser gets accessible name `JSEUIManager.81` and description `JSEUIManager.82`.
- Menus and menu items have accessible descriptions (`MainMenu.1`, `.3`, `.8`, `.10`, `.13`, `.16`, `.17`, …).
- Tooltips on icons and on the PDF preview image (`SignPdfUiPreview.26`).
- Tree views (signers tree in the signature viewer, `TreeFocusManager`): focus restores the last selected node, losing focus clears the selection; Space/Enter on a node with an action (open file link, signature info) triggers it; hand cursor on actionable nodes.
- Link labels (`LabelLinkManager`) are focusable, open with Space/Enter or click.
- HTML panes with several links (`EditorFocusManager`, used in the PDF preview info text): the pane is focusable; Right/Down and Left/Up arrows cycle through the hyperlinks (wrapping), Space/Enter activates the focused link; the focused link is highlighted with selection colours; focus traversal re-enters at the remembered link.
- The bundled Windows JRE enables the **Java Access Bridge** (`jre/conf/accessibility.properties`: `assistive_technologies=com.sun.java.accessibility.AccessBridge`, `screen_magnifier_present=true`) so JAWS/NVDA can read Swing UIs.

### 12.4 Keyboard operation

General rules:
- All screens are reachable with Tab/Shift+Tab. In the custom (Nimbus/Metal) L&F `Button.defaultButtonFollowsFocus=true`: Enter activates the focused button.
- In the visible-signature text area, Tab/Shift+Tab move focus instead of inserting a tab character.
- Esc closes most secondary dialogs on Windows/Linux (not on macOS, where Cmd+. / window controls are used).
- On macOS, menu-item mnemonics for "Abrir" and "Ayuda" are not set (Apple HIG) and Quit/About/Preferences come from the application menu (Cmd+Q, Cmd+, provided by the system).
- Accelerators use the platform menu modifier (`Toolkit.getMenuShortcutKeyMask()`: Ctrl on Windows/Linux, Cmd on macOS).

Complete list of keyboard shortcuts found in the original:

| Context | Key | Action / control (Spanish label, message key) |
|---|---|---|
| Main menu | (none effective) | Menu "Archivo" (`MainMenu.0`) – Quirk: mnemonic set to `VK_ALT`, which does nothing (the doc comment claims Alt+A) |
| Main menu › Archivo | Ctrl/Cmd+A; mnemonic B (not macOS) | "Abrir archivo a firmar" (`MainMenu.2`) – Gotcha: conflicts with Select-All |
| Main menu › Archivo | Ctrl/Cmd+V; mnemonic V | "Ver firma" (`MainMenu.34`) – opens a signature file (csig, xsig, pdf, sig, p7s) in the viewer – Gotcha: conflicts with Paste |
| Main menu › Archivo | Alt+F4; mnemonic L | "Salir" (`MainMenu.7`) – not on macOS |
| Main menu | Alt+R (mnemonic) | Menu "Herramientas" (`MainMenu.32`) |
| Main menu › Herramientas | Ctrl/Cmd+R; mnemonic R | "Restaurar instalación" (`MainMenu.20`) |
| Main menu › Herramientas | Ctrl/Cmd+G; mnemonic G | "Gestionar plugins" (`MainMenu.37`) |
| Main menu › Herramientas | Ctrl+P; mnemonic P | "Preferencias" (`MainMenu.12`) – not on macOS (app menu instead) |
| Main menu › Idioma | Ctrl/Cmd+I | "Importar idioma" (`MainMenu.45`) |
| Main menu | Alt+Y (mnemonic) | Menu "Ayuda" (`MainMenu.9`) |
| Main menu › Ayuda | F1; mnemonic U (not macOS) | "Ayuda de Autofirma" (`MainMenu.11`) |
| Main menu › Ayuda | Ctrl+C; mnemonic C | "Acerca de Autofirma" (`MainMenu.15`) – not on macOS – Gotcha: conflicts with Copy |
| DNIe wait screen | Alt+C | "Continuar con DNIe" (`DNIeWaitPanel.4`) |
| DNIe wait screen | Alt+U | "Usar almacén por defecto" (`DNIeWaitPanel.0`) |
| DNIe wait screen | Esc | Same as "Usar almacén por defecto" |
| DNIe wait screen | F1 (not macOS) | Opens help |
| Sign screen | Alt+S | "Seleccionar ficheros a firmar" (`SignPanel.32`) |
| Sign screen | Alt+F | "Firmar" (`SignPanel.45`) |
| Sign screen (file info) | Alt+C | "Ver Fichero" (`SignPanel.51`) / "Ver fichero" (`SignDataPanel.3`) |
| Sign screen | Alt+A | "Opciones Avanzadas" (`SignPanel.119`) |
| Sign screen | Enter/Space on the format/option links | Open "change format"/advanced dialogs (`SignatureConfigInfoPanel`) |
| Sign screen (multi-file list) | Enter | Open the selected data file |
| Result screens | Alt+M | "Firmar más ficheros" (`SignDetailPanel.0`) |
| Mass-sign result | Alt+B | "Abrir directorio" (`MassiveResultProcessPanel.4`) |
| Mass-sign result list | Enter | Open selected signature in the viewer |
| Signature viewer | Alt+V | "Ver otra firma" (`VisorPanel.1`) |
| Signature viewer | Alt+C | "Cerrar visor" (`VisorPanel.0`) |
| Signature viewer | Esc | Close viewer |
| Signers tree | Space/Enter | Activate node action |
| Close confirmation | Alt+M | Checkbox "No volver a mostrar este mensaje" (`ClosePanel.0`) |
| Data debug dialog | Alt+C | "Continuar" (`DataDebugDialog.8`) |
| Data debug dialog | Ctrl+R | Reload data from another file (debug only) |
| Preferences | Alt+G / Alt+F / Alt+E / Alt+X / Alt+L / Alt+N | Tabs "General" (`PreferencesPanel.2`), "Firmas PAdES (PDF)" (`.3`), "Firmas CAdES" (`.4`), "Firmas XAdES" (`.5`), "Factura Electrónica" (`.100`), "Almacenes de claves" (`.192`) |
| Preferences | Alt+C / Alt+A / Alt+P | "Cancelar" (`.31`), "Aceptar" (`.33`), "Aplicar ahora" (`.0`) |
| Preferences | Esc (not macOS) | Close (cancel) |
| Preferences › General | Alt+I / Alt+G / Alt+R | "Importar configuración" (`.107`), "Exportar configuración" (`.196`), "Restaurar configuración" (`.135`) |
| Preferences › General | Alt+O / Alt+D / Alt+Y / Alt+T | "Configurar formatos" (`.162`), "Dominios seguros" (`.185`), "Configurar proxy" (`.126`), "Certificados de confianza" (`.194`) |
| Preferences › PAdES/CAdES/XAdES | Alt+R / Alt+P | "Restaurar configuración" (`.147`), "Configurar política" (`.150`) |
| Preferences › Factura-e | Alt+R | "Restaurar configuración" (`.147`) |
| Preferences › Keystores | Alt+V / Alt+T / Alt+J / Alt+I / Alt+M / Alt+R | "Ver contenido" (`PreferencesPanelKeyStores.2`), "Conectar" (`.10`), "Agregar tarjeta" (`.11`), "Modificar" (`.23`), "Eliminar" (`.24`), "Restaurar configuración" (`PreferencesPanel.147`) |
| Default formats dialog | Alt+R | "Reestablecer" (`DefaultFormatPanel.2`) |
| Proxy dialog | Alt+V / Alt+A | "Verificar conexión" (`ProxyDialog.8`), "Autodetectar" (`ProxyDialog.11`) |
| Restore configuration | Alt+R / Alt+C / Esc (not macOS) | "Iniciar restauración" (`RestoreConfigPanel.1`), "Cerrar" (`.5`), close |
| Plugins management | Alt+A / Alt+E / Alt+C / Esc (not macOS) | "Agregar" (`PluginsManagementPanel.1`), "Eliminar" (`.2`), "Cerrar" (`.5`), close; permissions dialog also closes with Esc |
| PDF visible signature – area selection (`SignPdfUiPanel`) | Alt+A | "Siguiente" (`SignPdfUiPanel.0`) – mnemonic letter not in label (quirk) |
| PDF – area selection | Alt+C / Esc | "Cancelar" (`SignPdfUiPanel.3`) / cancel |
| PDF – area selection | Left / Right (outside text fields) | Previous / next page; Right on the last page appends a new blank page when the dialog is not in `isSignPdf` mode (page-append mode, see §3). The rectangle can also be typed in the X / Y / width / height numeric fields. |
| PDF – appearance (`SignPdfUiPanelPreview`) | Alt+R / Alt+A / Alt+C / Esc | "Restaurar configuración" (`SignPdfUiPreview.31`), "Aceptar" (`.5`), "Cancelar" (`.6`), cancel |
| PDF – appearance | Ctrl+N / Ctrl+K / Ctrl+S / Ctrl+T | Toggle bold (N=Negrita) / italic (K=Cursiva) / underline (S=Subrayado) / strikethrough (T=Tachado) |
| PDF – appearance | Ctrl+P | Select the signature image (rubric) |
| PDF – image stamp (`SignPdfUiPanelStamp`) | Alt+A / Alt+C / Esc / Left / Right | "Aceptar" (`SignPdfUiStamp.8`), "Cancelar" (`.10`), cancel, page navigation |
| Certificate selection dialog | F1 | Online help `https://github.com/ctt-gob-es/clienteafirma/wiki/Help-desktop-select-certs-<ll>-<CC>` |
| Certificate selection dialog | F5 | Reload the keystore |
| DNIe/smart-card PIN dialog | Ctrl+P | Show/hide PIN (eye button) |
| DNIe/smart-card PIN dialog | Ctrl+V or Shift+Insert / Backspace / Delete | Paste into secure PIN field / delete last char / clear |
| DNIe/smart-card PIN dialog | Enter / Esc; Alt+A / Alt+C; Alt+E | Accept / cancel; buttons Aceptar / Cancelar; checkbox "use PIN cache" |
| DNIe/smart-card dialogs | Alt+R / Alt+M | Restore / maximise window size (font scales) |
| Smart-card confirmation dialog | Enter / Esc; Alt+S | Confirm / cancel |
| Hash plugin dialogs (§7) | Alt+E, Alt+X (browse buttons), Alt+G (generate), Alt+R (recursive checkbox / check), Alt+C (check / close), Esc (not macOS) | Create/check hash of file/directory |

### 12.5 Requirements for the Rust port

- Expose every control to the platform accessibility API with name, role, description and state; keep the Spanish accessible names/descriptions from the bundles (they are part of the localized catalogue).
- Full keyboard operability of all flows (file selection, format change, visible-signature placement — keep the numeric X/Y/width/height fields of the original and add arrow-key nudging of the rectangle).
- Respect OS high-contrast, dark mode, text scaling and reduced-motion settings; minimum 4.5:1 contrast for custom colours.
- Replace clashing accelerators (Ctrl+A/C/V) with conventional ones (e.g. Ctrl+O open, Ctrl+Shift+O view signature, F1 help) while keeping mnemonics; document the change in the release notes.
- Announce asynchronous results (signature finished, validation result, errors) via live regions/notifications.


## 13. Parity checklist

One row per feature that the Rust implementation must reproduce (or consciously drop). "Java class(es) / file(s)" points at the original source for traceability; "Notes" gives the section with the full specification and the main caveats. Rows marked as legacy/unused in the notes may be skipped.

### 13.1 Start-up, logging, theming, proxy, help, updater, i18n, accessibility (§1, §8, §11, §12)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| Entry point & argv classification (GUI / afirma:// / CLI / -help / headless) | `SimpleAfirma.main`, `isUsingCommandLine`, `isHeadlessMode` | §1.3; bare file path = unknown CLI command; no `-version` |
| Windows/Linux/macOS launchers (JVM opts, splash.bmp, console exe, macOS GetURL stub) | `Autofirma_launch4J_project_*.xml`, `AutofirmaCommandLine_launch4J_project_*.xml`, `/usr/bin/autofirma`, `afirma.desktop`, `Lanzador/AppDelegate.m` | §1.1 |
| Protocol dispatch by URL prefix (websocket/service/batch/selectcert/save/signandsave/sign/cosign/countersign/load) | `ProtocolInvocationLauncher.launch` | §1.4; details in protocol spec |
| Single-instance lock for desktop GUI | `SimpleAfirma.isSimpleAfirmaAlreadyRunning` (`~/.afirma/Autofirma/.lock`) | §1.9; protocol & CLI modes not locked |
| DNIe start screen conditions and transitions | `SimpleAfirma.initGUI`, `propertyChange`, `DNIeWaitPanel` | §1.5; needs a PC/SC reader + pref `hideDnieStartScreen=false` |
| Default keystore loading / fallback to OS store | `SimpleAfirma.getAOKeyStoreManager`, `loadDefaultKeyStore`, `SimpleKeyStoreManagerWorker` | §1.5 (details §3/§4) |
| Linux early NSS preload + JMulticard enable | `SimpleAfirma.main`, `JMulticardUtilities` | §1.3/§1.10 |
| Main window sizing, title, icons, maximise on ≤600 px | `MainScreen`, `DesktopUtil.getIconImages`, `LookAndFeelManager.needMaximizeWindow` | §1.6 |
| Close confirmation with "don't ask again" | `SimpleAfirma.askForClosing`, `ClosePanel` | §1.6; pref `omitAskOnClose` written on toggle |
| Exit codes | `SimpleAfirma.closeApplication/forceCloseApplication`, `CommandLineLauncher.closeApp` | §1.7 (0 / −1) |
| File logging (XML, 2 MiB, truncated per run) + debug switches | `LogManager`, `SimpleAfirma.configureLog/configureFileLogger` | §1.8; `afirma_debug`, `afirma_debug_level` |
| App directories (home, alternative, install, plugins, languages) | `SimpleAfirma.APPLICATION_HOME`, `DesktopUtil.getApplicationDirectory/getAlternativeDirectory` | §1.9 |
| Env vars / system properties honoured and set | `SimpleAfirma`, `HttpManager`, `ProxyUtil`, `JMulticardUtilities`, `SSLContextConfigurationTask` | §1.10 |
| Protocol-mode progress "splash" (dlgload + enableProgressDialog) | `ProgressInfoDialogManager`, `ProgressInfoDialog` | §1.11 |
| Look&Feel selection, high contrast, large font, GNOME dark (broken), HiDPI device list | `LookAndFeelManager`, `HDPIManager`, `/lookandfeel/hdpi_devices` | §1.12 |
| Proxy NONE/SYSTEM/CUSTOM application, proxy auth | `ProxyUtil`, `ProxyConfig` | §1.13; proxy-vole auto-detection |
| Proxy password obfuscation (AES-CBC fixed key/IV, DES legacy) | `ProxyUtil.cipherPassword/decipherPassword`, `AesServerCipher`, `DesServerCipher` | §1.13; must read existing values |
| Secure connections, secure domains wildcard list, trust managers, auto-import block | `SSLContextConfigurationTask`, `HttpManager`, `UrlHttpManagerImpl.checkIsSecureDomain` | §1.14 |
| WebSocket TLS keystore presence check at GUI start | `CheckTrustKeyStoreTask`, `SecureSocketUtils.getSecureSSLContext` | §1.5; error 200801 |
| Java version warning | `SimpleAfirma.checkJavaVersion` | §1.5; drop in Rust (pref `checkJavaVersion`) |
| Local HTML help extraction & opening (help.version, fileslist.txt, local_launcher.html) | `SimpleAfirma.showHelp`, `HelpResourceManager` | §1.15; fileslist.txt missing newline bug |
| macOS About/Preferences/Quit handlers, dock icon, PCSC fix | `OSXHandler`, `MainMenu`, `SimpleAfirma.main` | §1.16 |
| macOS helpers (osascript, admin shell, focus, kill, app path) | `so/macos/AppleScript`, `ShellScript`, `MacUtils`, `UnixUtils` | §1.16 |
| Application restart after language change | `DesktopUtil.getResetApplicationCommand/getCommand`, `MainMenu.showRestartWarning` | §1.17 |
| Error code catalogue | `SimpleErrorCode` | §1.18 |
| Remote system-config refresh thread at GUI start | `ConfigUpdaterManager.needCheckConfigUpdates/updatePrefsConfigFile` | §1.3 (details §4) |
| New-version notifier (per-OS URL, integer build compare, once/day, opt-outs) | `updater/Updater`, `UpdaterMessages`, `properties/updater.properties` | §8 |
| Update opt-outs | `SimpleAfirma.AVOID_UPDATE_CHECK(_ENV)`, `setUpdatesEnabled`, pref `checkForUpdates` | §8.3 |
| Six built-in languages + language menu + restart prompt | `LanguageManager.AFIRMA_DEFAULT_LOCALES`, `MainMenu`, `LocaleOption` | §11.1–11.2 |
| Language pack import (ZIP with metadata.info, bundles, help) | `LanguageManager.addLanguage`, `MainMenu.addNewLocaleToMenu` | §11.3 |
| Message lookup with 4-level fallback and %n placeholders | `SimpleAfirmaMessages` and sibling `*Messages` classes | §11.4 |
| Resource bundle inventory and locale gaps | `properties/*/*.properties`, module bundles | §11.5 |
| Configurator `-language_path` / `-default_language` | `AutofirmaConfigurator.main` | §11.2 (details §9) |
| High-contrast adaptations, link styling | `LookAndFeelManager.WINDOWS_HIGH_CONTRAST`, `LabelLinkManager`, `EditorFocusManager` | §12.1 |
| Font/image auto-scaling | `ResizingTextPanel`, `ScalablePane`, jmulticard `ResizingAdaptor` | §12.2 |
| Screen-reader names/descriptions, label-for, Java Access Bridge | all UI classes, `JSEUIManager`, `java64/jre/conf/accessibility.properties` | §12.3 |
| Keyboard shortcuts & mnemonics (full table) | `MainMenu`, panels, `PreferencesPanel*`, `SignPdfUiPanel*`, `CertificateSelectionDispatcherListener`, jmulticard dialogs, hash dialogs | §12.4; Ctrl+A/C/V clashes |
| Tree/link keyboard focus management | `TreeFocusManager`, `LabelLinkManager`, `EditorFocusManager` | §12.3 |

### 13.2 GUI: main window, sign flow, results, viewer, menus (§2)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| Main window frame, panel switching, title, macOS document proxy, 780×580, maximise on ≤600 px screens | `SimpleAfirma`, `ui/MainScreen` | §2.1; state machine DNIE_WAIT → SIGN → RESULT_SINGLE/RESULT_MULTI → SIGN |
| DNIe wait start screen (reader detection, Continue with DNIe / default store, ESC, F1, "do not show again") | `ui/DNIeWaitPanel`, `SimpleAfirma.initGUI/propertyChange` | §2.2; pref `hideDnieStartScreen`; shown only if a PC/SC reader exists |
| Sign screen: welcome text, "Seleccionar ficheros a firmar" (multi-select), drop zone, Sign button with keystore-loading spinner | `ui/SignPanel` (UpperPanel/LowerPanel), `ui/ResizingTextPanel` | §2.3 |
| Drag & drop of files/dirs (local only, recursive directory expansion) | `ui/DropDataFileListener`, `SignPanel.filterFiles` | §2.3.2/§2.3.4; http/https/ftp entries ignored |
| File-type detection by content (PDF, FacturaE, OOXML, ODF, XML, signatures, binary) | `DataAnalizerUtil`, `SignPanel.configureDataSigner`, `AOSignerFactory` | §2.4.2; extensions never used |
| Default signature format per file type from preferences | `SignPanel.configureDataSigner` | §2.4.2; `defaultSignatureFormat{Pdf,Facturae,Ooxml,Odf,Xml,Bin}` |
| Per-file operation model | `ui/SignOperationConfig`, `ui/FileType` | §2.4.1/§2.4.3 |
| Format display names | `SignPanel.getSignatureName` | §2.4.4 |
| Pre-validation of inputs that are already signatures and the error texts shown | `SignPanel.setValidationInfo/buildErrorText`, afirma-crypto-validation `SignValiderFactory` | §2.4.5 |
| Preferences → signer extra params (policy, roles, place, PAdES reason/contact/subfilter/obfuscation, CAdES mode, XAdES format) | `ui/ExtraParamsHelper` | §2.4.6 |
| Change signature format dialog with "(Recomendado)" | `ui/ChangeFormatPanel`, `ui/preferences/FormatItem`, `SignatureConfigInfoPanel.ChangeFormatListener` | §2.4.7 |
| Co-sign/counter-sign selection from preferences for existing CAdES/XAdES signatures | `SignPanel.setMultisignOpFromPreferences` | §2.4.8; `cadesMultisign`, `xadesMultisign` |
| Single-file info panel (path, type, date, size, validation result, config, attributes summary, PDF visible/stamp/certified options, Advanced options, View file) | `ui/SignPanelFilePanel`, `ui/DocumentInfoPanel`, `ui/ValidationInfoPanel`, `ui/SignatureConfigInfoPanel` | §2.5 |
| Multi-file list (relative paths, format, size, invalid in red, double-click/Enter open, context menu) | `ui/SignPanelMultiFilePanel` | §2.6 |
| Confirm-before-sign dialog with "omit in future" | `ui/ConfirmSignatureDialog` | §2.7 step 3; pref `confirmToSign` |
| Sign orchestration: wait dialog, PDF visible signature step, cert selection with filters, output dir, per-file signing loop, error handling, PIN retry, runtime confirmations/password, relaunch | `SignPanel.sign/initSignTask/relaunchTask/finishTask`, `ui/SignPanelSignTask`, `ui/SignatureExecutor`, `ui/CommonWaitDialog` | §2.7 |
| Visible-signature page/position auto-recovery and warning list | `SignPanelSignTask.signData` | §2.7 step d.8/h |
| Batch output naming and overwrite numbering `name(n).ext` | `SignPanelSignTask.saveDataToFile` | §2.7 step d.11; pref `massiveOverride` |
| Single-file save dialog with per-format filters and `_signed` names | `SignPanelSignTask.saveSignature`, signers' `getSignedName` | §2.7 step f |
| Plugin pre/post-sign hooks and reset | `SignPanelSignTask.pluginsPreProcess/PostProcess/Reset` | §2.13; detail §7 |
| Validation of the generated signature for the result screen | `SimpleAfirma.showResultsInfo` | §2.8.1; OOXML/ODF bug noted |
| Single result screen (status header, VALIDe link, details link, signed-file box, cert box, signature tree, "Firmar más ficheros") | `ui/SignDetailPanel`, `ui/SignResultPanel`, `ui/SignDataPanel` | §2.8.2 |
| Signature data tree (format, signed data link, signers tree, timestamps) | `SignDataPanel.getSignDataTree`, `ui/TreeModelManager`, `ui/LinksTreeCellRenderer`, `ui/TreeFocusManager`, `crypto/CompleteSignInfo`, `crypto/TimestampsAnalyzer` | §2.8.2 |
| Certificate summary (DNIe vs generic; open cert in OS viewer) | `crypto/CertAnalyzer`, `crypto/DnieCertAnalyzer`, `crypto/GenericCertAnalyzer`, `crypto/CertificateInfo`, `ui/CertInfoLabelLinkImpl`, `SignDataPanel.openCertificate` | §2.8.2 |
| Signed-data info dialog (open/save extracted data) | `ui/ShowFileLinkAction`, `ui/DataFileInfoDialog`, `ui/DataFileAnalizer`, `ui/DataFileInfo`, `ui/FileIconProvider` | §2.8.2 |
| Multi result screen (output dir, open dir, cert, per-file OK/KO table, open in viewer) | `ui/SignResultListPanel`, `ui/MassiveResultProcessPanel` | §2.8.3 |
| Signature details & validation errors dialog (HTML report) | `ui/ValidationInfoDialog`, `ui/ValidationErrorsLabelLinkImpl`, `signdetails/*` (`SignDetailsFormatter`, `SignDetails`, `CAdESSignAnalyzer`, `XAdESSignAnalyzer`, `PAdESSignAnalyzer`, `FacturaESignAnalyzer`, `CertificateDetails`, `DataObjectFormat`, `SignaturePolicy`) | §2.9 |
| Validity categories, icons and texts | afirma-crypto-validation `SignValidity`, `validationmessages_*.properties` | §2.9 table |
| Signature attributes dialog | `ui/SignatureAttributesDialog` | §2.10 |
| Signature viewer window (standalone or modal), "Ver otra firma", "Cerrar visor", ESC | `VisorFirma`, `ui/VisorPanel` | §2.11; CLI `verify -gui` |
| Menu bar: Archivo/Herramientas/Idioma/plugin menus/Ayuda, accelerators, macOS app-menu handlers | `ui/MainMenu`, `ui/OSXHandler`, `ui/LocaleOption` | §2.12 |
| Language switch + import language zip + restart prompt | `MainMenu` (language items, `showRestartWarning`, `addNewLocaleToMenu`) | §2.12; zip format §11 |
| About dialog | `ui/AboutDialog` | §2.12 |
| Close confirmation with "do not show again" | `SimpleAfirma.askForClosing`, `ui/ClosePanel` | §2.12; pref `omitAskOnClose` |
| Plugin buttons per window and plugin menus | `ui/PluginsUiComponentsBuilder`, `ui/PluginGraphicButton`, `ui/PluginIntegrationWindow`, `ui/PluginButtonsContainer` | §2.13; detail §7 |
| Link-style labels (mouse/Enter/Space, focus styling, high contrast) | `ui/LabelLinkManager`, `ui/LabelLinkListener`, `ui/URLLabelLinkImpl` | §2.5, §2.15 |
| Progress popup for protocol invocations (`dlgload`) | `ui/ProgressInfoDialog`, `ui/ProgressInfoDialogManager`, `ui/RoundedPanel` | §2.14; pref `enableProgressDialog` |
| Debug "data to sign" dialog (`-DAFIRMA_SHOW_DATA_TO_SIGN=true`) | `ui/DataDebugDialog` | §2.14; optional |
| Copy-path popup | `ui/CopyMenuItem` | §2.8.2/§2.8.3 |
| Image loading/scaling helpers | `ui/ImageLoader`, `ui/ScalablePane` | §2.14 |
| HTML hyperlink keyboard navigation (used by PDF dialogs) | `ui/EditorFocusManager`, `ui/EditorFocusManagerAction` | §2.14; used in §3 |
| Error pane with stack trace | `ui/ErrorPane` | Dead code; not needed |

### 13.3 GUI: visible PDF signature, keystores, certificate selection, generic dialogs (§3)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| Visible-signature trigger in GUI (checkbox/prefs, certificationLevel, clone configs, fallback to invisible) | `ui/SignPanel` (PDF branch), `ui/SignatureConfigInfoPanel` | §3.1.1; quirk: multi-file reads `padesVisibleSignature` instead of `allowCertifiedPDF` |
| Visible-signature orchestration (empty fields → chooser → dialog → apply params to all PDFs) | `ui/pdf/VisiblePdfSignatureManager` | §3.1.2; GUI cancel ⇒ invisible signature |
| Empty signature-field chooser (use / create new / cancel) | `ui/pdf/PdfEmptySignatureFieldsChooserDialog.selectField`, `PdfUtil.getPdfEmptySignatureFields` | §3.2; full preview dialog is dead code |
| Visible-signature container dialog, password prompt, panel state machine, min area 30×45/1350 | `ui/pdf/SignPdfDialog`, `ui/pdf/PdfLoader` | §3.3 |
| PDF page rendering at 75 DPI with lazy ±4 page window; rotated page sizes | `ui/pdf/Pdf2ImagesConverter`, `ui/pdf/PdfDocument`, `ui/pdf/SignPdfUiUtil` | §3.4 |
| Signature area selection (rubber band, X/Y/W/H fields, page nav, append blank page, page range) | `ui/pdf/SignPdfUiPanel`, `ui/pdf/PageLabel`, `ui/pdf/NaturalNumbersDocFilter`, `PdfUtil.checkPagesRangeInputFormat` | §3.5; coordinate quirks documented |
| Signature appearance editor (text template, font/size/style/colour/rotation, rubric image, DnD, preview, remember/restore prefs, shortcuts) | `ui/pdf/SignPdfUiPanelPreview`, `ui/pdf/FontResource`, `ui/pdf/ColorResource` | §3.6; prefs `pdfLayer2*`, `pdfSignatureRotation`, `pdfSignatureImage` |
| Visible stamp/image mark panel (image, page or all pages, position) | `ui/pdf/SignPdfUiPanelStamp` | §3.7; params `image`, `imagePage`, `imagePositionOnPage*` |
| Exact extra-params emitted by PDF UI | `PdfExtraParams` (afirma-crypto-pdf-common) | §3.8 table |
| Protocol visible-signature dialog (`visibleSignature=want/optional`, `visibleAppearance=custom`, mandatory enforcement) | `protocol/ProtocolInvocationLauncherSign`, `ProtocolInvocationLauncherSignAndSave` (`showRubricPositionDialog`, `SignPdfListener.updateOptions`) | §3.9 |
| UI message bundle for PDF dialogs | `ui/pdf/SignPdfUiMessages`, `signpdfuimessages_*.properties` | §3 intro; `%N` substitution |
| Keystore name table and OS defaults | `AOKeyStore` (afirma-core-keystores) | §3.10.1; names persisted in `defaultKeystore` |
| Keystore name resolution and default-store validation | `SimpleKeyStoreManager.getKeyStore`, `getDefaultKeyStoreType`, `getValidKeyStoreType`, `isFirefoxAvailable` | §3.10.2 |
| Desktop keystore loading with DNIe handling and fallbacks | `SimpleKeyStoreManager.getKeyStore(dnie,forced,parent)`, `SimpleKeyStoreManagerWorker`, `NoDnieFoundException`, `SimpleAfirma.loadDefaultKeyStore/getAOKeyStoreManager` | §3.10.3 |
| Linux early NSS (Firefox) preload | `SimpleAfirma.main` (preload block) | §3.10.3 |
| JMulticard enable/disable (JVM props + env vars) | `JMulticardUtilities`, `KeyStoreUtilities` constants | §3.10.4; pref `enabledJmulticard` |
| Protocol keystore precedence and background preload | `ui/tasks/LoadKeystoreTask`, `ProtocolInvocationLauncher.initLoadKeyStoreTask`, `ProtocolInvocationLauncherUtil.getAOKeyStoreManager` | §3.10.5 |
| Registered PKCS#11 smart cards (user/system prefs nodes, naming, last-selected keystore memory) | `KeyStorePreferencesManager` (afirma-core-prefs) | §3.10.6 |
| Certificate selection invocation, filters from prefs, auto-select, PIN-error reselection | `ui/SignPanelSignTask.getPrivateKeyEntry`, `SignPanel.getCertFilters`, `AOKeyStoreDialog`, `KeyUsageFilter`, `SkipAuthDNIeFilter`, `PseudonymFilter`, `EncodedCertificateFilter` | §3.11.1 |
| Certificate selection dialog UI (toolbar refresh/change store/help/views, card rows, icons, tooltips, view-cert link, F1/F5, double-click, `certView` pref) | `CertificateSelectionDialog`, `CertificateSelectionPanel`, `CertificateSelectionDispatcherListener`, `DefaultCertificateLine`, `RepresentativeCertificateLine`, `PseudonymCertificateLine`, `CertificateIconManager`, `CertificateUtils`, `UtilActions`, `JDropDownButton`, `PrincipalStructure` (afirma-ui-core-jse-keystores) | §3.11.2 |
| Keystore switching from dialog (system/Firefox/PKCS#12/DNIe/registered cards; Linux restriction) | `AOKeyStoreDialog.changeKeyStoreManager`, `changeKeyStoreManagerToPKCS11`, `getAvailablesKeyStores`, `openPkcs12KeyStore` | §3.11.2 |
| Key-usage text in certificate rows | `KeyUsage.toString` (afirma-core), `coremessages` | §3.11.2; "Firma y cifrado" unreachable |
| Smart-card PIN dialog with 1 h cache and DNIe confirmation | `InputPasswordSmartcardDialog`, `DnieCacheCallbackHandler`, `SmartcardCacheCallbackHandler` (afirma-keystores-jmulticard-ui) | §3.11.3 (brief) |
| TLS/HTTP context configuration at startup (secure connections, secure domains, personal truststore, test connection) | `ui/tasks/SSLContextConfigurationTask`, `SslSecurityManager.configureAfirmaTrustManagers`, `TrustStoreManager` | §3.12; truststore `~/.afirma/TrustedCertsKeystore.jks` / `changeit` |
| Local WebSocket TLS keystore presence check (`autofirma.pfx`, `654321`) | `ui/tasks/CheckTrustKeyStoreTask`, `protocol/SecureSocketUtils` | §3.12 |
| UI manager selection (AWT on macOS, Swing elsewhere) | `AOUIFactory`, `AWTUIManager`, `JSEUIManager` | §3.13.1 |
| Password and double-password dialogs | `JSEUIManager.getPassword`, `getDoublePassword` | §3.13.2–3 |
| Open-file dialog with remembered directory (`currentDir` pref) and macOS native dialog | `JSEUIManager.getLoadFiles`, `AWTUIManager.getLoadFiles`, `configureDefaultDir` | §3.13.4 |
| Save-file dialog (filters, extension auto-append, overwrite Yes/No/Cancel loop) | `JSEUIManager.saveDataToFile`, `CustomFileChooserForSave`, `AWTUIManager.saveDataToFile` | §3.13.5 |
| Confirm/message/input dialogs | `JSEUIManager.showConfirmDialog/showMessageDialog/showInputDialog` | §3.13.6 |
| Error dialog with `AFxxxx` code, icon, Close button (no details) | `errors/ErrorManagementDialog`, `ErrorManagementPanel`, `ErrorManagementHandler` | §3.13.6 |
| Wait / progress dialogs (`dlgload`, `enableProgressDialog`) | `ui/CommonWaitDialog`, `ui/ProgressInfoDialog`, `ui/ProgressInfoDialogManager` | §3.13.7 |
| Signer-tree model conversion for viewer | `JSEUtils.convertToSwingModel` | §3.13.8 |
| Generic dialog texts | `JSEUIMessages`, `uimessages_*.properties` | §3 intro |

### 13.4 Preferences (§4)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| Three-layer preference resolution (user → system → default) and "do not shadow" writes | `PreferencesManager` (afirma-ui-simple-configurator-common), `properties/preferences.properties` | Keep exact key names; read legacy Java stores (§4.2) |
| Per-OS preference storage (HKCU/HKLM `Software\JavaSoft\Prefs\es\gob\afirma\…`, macOS `com.apple.java.util.prefs.plist`, Linux `~/.java/.userPrefs` & `/etc/.java/.systemPrefs`) | JDK `java.util.prefs`, `PreferencesManager`, `KeyStorePreferencesManager` | Decode Windows escaping (`/X`, `\`↔`/`, `/uXXXX`) for migration/admin values |
| Built-in defaults for every key | `preferences.properties` | Table in §4.5; OOXML/ODF default = CAdES |
| Preferences locking (`preferencesBlocked`) and protected-key list | `PreferencesManager.PREFERENCE_GENERAL_BLOCKED`, `isProtectedPreference`, all `PreferencesPanel*` `setBlocked` | Java lock is UI-only and user-overridable; port should enforce system precedence |
| Admin-only keys (`requireSignedPrerefences`, `certHashToSignedPrerefences`, `allowPersonalTruststore`, `allowAutoImportTrustedCerts`) | `PreferencesManager`, `PreferencesPlistHandler`, `SSLContextConfigurationTask`, `PreferencesPanelGeneral` | Misspelled names must be preserved; require-signed bug |
| Internal system keys (`configFileUrl`, `allowUpdateConfig`, `configFileSHA256`, `configDate`) | `PreferencesManager` internal node | Never exported; exclusive keys system-only |
| Env/JVM overrides (`AUTOFIRMA_AVOID_UPDATE_CHECK`, `es.gob.afirma.doNotCheckUpdates`, `AFIRMA_NSS_DISABLE_DNIE/CERES_NATIVE_DRIVER`) | `SimpleAfirma`, `JMulticardUtilities`, `KeyStoreUtilities` | Hide/disable corresponding checkboxes |
| Preferences dialog (6 tabs, Aplicar/Aceptar/Cancelar, Esc, macOS button order, validation order, save order) | `PreferencesDialog`, `PreferencesPanel`, `ModificationListener`, `DisposableInterface` | Opened from menu (Ctrl+P), macOS app menu, "Opciones Avanzadas" (tabs 2/3) |
| General tab (close confirm, updates, JMulticard, VDI, progress dialog, digest algorithm, confirm-to-sign, invalid-signature policy, massive overwrite, secure connections) | `PreferencesPanelGeneral`, `HttpManager`, `AfirmaWebSocketServerManager`, `ProgressInfoDialog`, `SignPanel`, `SignPanelSignTask` | JMulticard checkbox Windows+Linux only; VDI Windows only |
| Default format per file type sub-dialog | `DefaultFormatPanel`, `FormatItem`, `SignPanel.configureDataSigner`, `ChangeFormatPanel` | Reset button bypasses lock (quirk) |
| Signature policy sub-dialog (none / AGE 1.9 / custom; FacturaE 3.1/3.0) with validation codes 521000–521009 | `PolicyPanel`, `PolicyItem`, `AgePolicy`, `PreferencesPanelPades/Cades/Xades/FacturaE`, `afirma-core/policy.properties`, `AdESPolicy` | XAdES `urn:oid:` auto-prefix; AGE restricts XAdES formats; policy forces PAdES-BES |
| PAdES tab (subfilter, visible signature, obfuscation, stamp, shadow-attack check, certified PDF level, metadata) | `PreferencesPanelPades`, `SignatureConfigInfoPanel`, `SignPanel` | `allowShadowAttack=true` means check |
| CAdES tab (implicit/explicit, multisign operation, policy) | `PreferencesPanelCades`, `SignPanel.setMultisignOpFromPreferences` | Unknown multisign value → countersignTree |
| XAdES tab (format, multisign, policy, production place, claimed role) | `PreferencesPanelXades` | |
| FacturaE tab (policy 3.0/3.1, signer role, production place) | `PreferencesPanelFacturaE`, `RoleItem` | Qualifier never sent |
| Keystores tab (default store, browser-call usage, DNIe start screen, certificate filters, show content) | `PreferencesPanelKeystores`, `RegisteredKeystore`, `SimpleKeyStoreManager`, `LoadKeystoreTask`, `ProtocolInvocationLauncher*` | Index 0 stored as `default` |
| PKCS#11 smart-card registry (add/modify/delete/connect; user/system/updated nodes; `smartcards` in .afconfig) | `KeyStorePreferencesManager` (afirma-core-prefs), `SmartCardPanel`, `PreferencesPanelKeystores` | System import may write to unread node (bug) |
| Preferences → extraParams mapping per signer | `ExtraParamsHelper` | OOXML/ODF get CAdES params |
| Visible PDF signature appearance persistence (`pdfLayer2*`, rotation, image; "Recordar configuración") | `SignPdfUiPanelPreview`, `FontResource`, `ColorResource` | |
| Proxy configuration dialog + storage + reversible password cipher (AES-CBC fixed key/IV, DES fallback) | `ProxyPanel`, `ProxyPanelHandler`, `ProxyConfig`, `ProxyUtil`, `AesServerCipher`, `DesServerCipher` | Port to OS keyring; port field 4-digit quirk |
| Secure domains list (dialog, storage, wildcard matching that disables TLS checks) | `SecureDomainsPanel`, `SecureDomainsHandler`, `HttpManager`, `UrlHttpManagerImpl.checkIsSecureDomain` | `*` matches all hosts |
| Personal trusted certificates (JKS `~/.afirma/TrustedCertsKeystore.jks`, pwd `changeit`; import local/URL; delete; auto-import prompt) | `TrustedCertificatesPanel`, `ImportCertificatesDialog`, `ConfirmImportCertDialog`, `TrustStoreManager`, `SslSecurityManager`, `SSLContextConfigurationTask`, `SSLErrorProcessor` | Gated by `allowPersonalTruststore`/`allowAutoImportTrustedCerts` |
| `.afconfig` export (system ∪ user, booleans as `<true/>`/`<false/>`, smartcards dict, no DOCTYPE) | `PreferencesPlistHandler.exportPreferencesToXml`, `xmlwise/Plist` | Exports ciphered proxy password |
| `.afconfig` GUI import (file or Alt+click URL; XMLDSig verification, cert validity, optional cert pinning; confirmation; merge into user layer) | `PreferencesPlistHandler.importPreferences`, `XAdESValidator`, `SignatureInfo`, `ConfiguratorErrorCode`, `PreferencesPanelGeneral` | DOCTYPE rejected; require-signed logic inverted; error codes 2303xx/5220xx |
| System config import from installer (`-config_path`, `-update_config`, `-default_language`) | `ConfigUpdaterManager.savePrefsConfigFile`, `PreferencesPlistHandler.importSystemPreferencesFromXml`, `AutofirmaConfigurator(Silent)` | No signature check; TLS ignored for https |
| Remote daily configuration auto-update at desktop start | `ConfigUpdaterManager.needCheckConfigUpdates/updatePrefsConfigFile`, `ConfigDataInfo`, `SimpleAfirma` | SHA-256 change detection; `YYYYMMdd` week-year bug |
| Per-tab "Restaurar configuración" and global restore | `PreferencesPanel*.restorePreferences`, `PreferencesPanelGeneral.loadDefaultPreferences` | Immediate, not undone by Cancel |
| Auxiliary per-user settings (last directory, certificate view, PIN cache flags, updater last check, plug-in config) | `JSEUIManager`, `CertificateSelectionPanel`, `DnieCacheCallbackHandler`, `SmartcardCacheCallbackHandler`, `Updater`, `PluginsPreferences` | Node paths in §4.2.1 |
| Uninstall removal of system preference nodes | `PreferencesManager.removeSystemPrefs`, `KeyStorePreferencesManager.removeSystemPrefs` | Called by configurator `-uninstall` (§9) |

### 13.5 Command line and massive signing (§5, §6)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| CLI mode detection (first arg not `afirma://`, or headless JVM; HeadlessException fallback) | `SimpleAfirma.main`, `isUsingCommandLine`, `isHeadlessMode` | §5.1.1. A bare file path is treated as an unknown command. |
| CLI bootstrap (silence JUL/SLF4J console logs, LAF, plugin manager) | `CommandLineLauncher.main` | §5.1.2. Also silences the optional file log. |
| Windows console launcher `AutofirmaCommandLine.exe` (skips SimpleAfirma.main) | `AutofirmaCommandLine_launch4J_project_{32,64}.xml` | §5.1.3. Linux `/usr/bin/autofirma`; macOS `Contents/MacOS/AutofirmaCommandLine`. |
| CLI locale (pref `default.locale`, else OS locale) and message bundles | `CommandLineLauncher.processCommandLine`, `CommandLineMessages`, `commandlinemessages_*.properties` | §5.2. `!key!` for missing keys; en_US is incomplete. |
| Output on stdout only; exit codes 0 / -1 | `CommandLineLauncher.closeApp`, `printMessage` | §5.2, §5.11 |
| General help and per-command help texts | `CommandLineLauncher.buildGeneralSyntax`, `CommandLineParameters.build*SyntaxError` | §5.3.1, §5.3.2. Plugin commands are appended to the general help. |
| Case-insensitive command dispatch; plugin command fallback with COMMANDS permission | `CommandLineCommand.parse`, `CommandLineLauncher.getPluginCommand`, `PluginCommandAction.start` | §5.3 |
| Option parser (duplicates, missing values, alias/filter exclusivity, `~` expansion, validation order) | `CommandLineParameters` | §5.4 |
| Legacy accepted-but-ignored options `-operation`, `-hformat`, `-halgorithm`, `-r` | `CommandLineParameters` | §5.4.2 |
| `-store` mapping (auto/windows/mac/mozilla/dni/dnie/pkcs12:/pkcs11:) | `CommandLineLauncher.getKsm`, `cleanupPathFile` | §5.5. On Linux, `auto` means the shared NSS DB. |
| Certificate selection by alias, by filter (exactly one match), or by GUI (`-certgui`) | `CommandLineLauncher.signByCommandLine`, `filterCertificates`, `CertFilterManager`, `AOKeyStoreDialog` | §5.6 |
| `-config` extraParams parsing (literal `\n`; GUI variant splits on real newlines) | `CommandLineLauncher.buildProperties`, `loadSignConfig` | §5.7. Quirks listed there. |
| Countersign target via `-config target=tree` | `CommandLineLauncher.sign` (`EXTRA_PARAM_TARGET`) | §5.7 |
| Format auto-selection (pdf→PAdES, xml→XAdES, else CAdES) and signer factory | `CommandLineLauncher.selectFormatByData`, `getSigner` | §5.8. No auto FacturaE/OOXML/ODF. |
| Non-secure signer context for the CLI (file-path resources allowed) | `AOConfigurableContext.setSecureMode(false)` | §5.8 |
| Digest default sha512 and signature algorithm composition by key type | `CommandLineParameters.DEFAULT_ALGO`, `AOSignConstants.composeSignatureAlgorithmName` | §5.8 |
| `sign`/`cosign`/`countersign` console operations | `CommandLineLauncher.signByCommandLine`, `sign` | §5.9.1 |
| PAdES invisible-signature retry on bad page or position | `CommandLineLauncher.sign`, `removeSignaturePageProperties` | §5.9.1. Bug: `null` key prefix. |
| `sign -gui` (open GUI preloaded with the file; Windows "Firmar con Autofirma") | `CommandLineLauncher.signByGui`, `loadSignConfig`, `SimpleAfirma.initGUI`, `SignPanel.loadFiles` | §5.9.2. Inverted `-format` logic; drops `-config` and preference extra params; SHA-512 default. |
| `verify` console output (SignValidity lines) | `CommandLineLauncher.verifyByCommandLine`, `SignValidity.toString`, `validationmessages_*.properties` | §5.9.3. Always status 0; texts contain HTML entities. |
| `verify -gui` (viewer) | `CommandLineLauncher.verifyByGui`, `VisorFirma` | §5.9.4. Windows `.csig`/`.xsig` Verify verb. |
| `listaliases` (plain / XML) | `CommandLineLauncher.listAliasesByCommandLine` | §5.9.5. XML uses `<result>ok</result>`, no escaping. |
| `batchsign` XML three-phase batch (preurl/posturl) | `CommandLineLauncher.batchByCommandLine`, `BatchSigner.signXML` | §5.9.6. Result and errors are dropped (exit 0); the bundled server only supports JSON. |
| Hash plugin commands `createdigest` / `checkdigest` | `HashParameters`, `CreateHashCommand`, `CheckHashCommand`, `HashCommands` | §5.9.7, engine in §7 |
| XML response envelope `<afirma><result>…` | `CommandLineLauncher.buildXmlResponse` | §5.10. Not XML-escaped; parameter errors are never XML. |
| Error to message and status mapping; GUI error dialog when `-gui` was seen | `CommandLineLauncher.processCommandLine`, `CommandLineException.isUsingGui`, `showErrorDialog` | §5.11, §5.12 |
| OS shell verbs invoking the CLI (sign, verify, hash) | NSIS `Autofirma_NSIS_project_*.nsi`, hash `register.bat`, `.desktop` files | §5.13. The Windows command path is unquoted. |
| Desktop multi-file input expansion (recursive folders, unreadable files dropped) | `SignPanel.loadFiles`, `filterFiles`, `prepareSignConfig` | §6.1.1 |
| Multi-file pre-sign list (relative paths, invalid-signature marking, size format) | `SignPanelMultiFilePanel` | §6.1.2 |
| Sign flow: invalid-signature guard, confirm dialog, multisign op from prefs, PDF visible config | `SignPanel.sign`, `setMultisignOpFromPreferences`, `checkSignPDFOperationSign`, `ConfirmSignatureDialog` | §6.1.3. Bug: certified-PDF pref read from `padesVisibleSignature`. |
| Multi-file loop: certificate, then output dir, headless, per-file skip policy, PIN retry | `SignPanelSignTask.doSignature`, `signData`, `selectOutDir` | §6.1.4 |
| JVM system properties merged into extraParams | `SignPanelSignTask` (`addExtraParams(System.getProperties())`) | §6.1.4. Legacy hook. |
| Plugin pre/post-sign hooks and reset in the sign loop | `SignPanelSignTask.pluginsPreProcess`, `pluginsPostProcess`, `pluginsReset` | §6.1.4, §7 |
| Output naming `_signed` and `(n)` collision index; mirrored subdirectories; `massiveOverride` | `SignPanelSignTask.saveDataToFile`, `AOSigner.getSignedName` implementations | §6.1.4. Relative path computed by string length. |
| Single-file save dialog with per-signer file filter | `SignPanelSignTask.saveSignature` | §6.1.4 |
| Out-of-range visible-signature warning list | `SignPanelSignTask.invalidPageNumberFilesList`, `SignResultPanel.34` | §6.1.4 |
| Multi-file result screen (banner, open/copy output dir, signing cert, result list, plugin buttons) | `SignResultListPanel`, `MassiveResultProcessPanel`, `SignResultPanel`, `SimpleAfirma.showResultsInfo` | §6.1.5. No log file is written. |
| Legacy directory signing (sign/cosign/countersign, originalFormat, recursion, filter) | `DirectorySignatureHelper.massiveSign` (both overloads) | §6.2.2. Not used by the desktop app. |
| Legacy output naming `.signed`/`.cosign`/`.sign`/`.countersign` + `(n)`, path-traversal guard | `DirectorySignatureHelper.saveSignToDirectory`, `isParent` | §6.2.3 |
| Legacy `result.log` format and counters | `DefaultLogHandler`, `LogHandler`, `massivesignmessages*.properties` | §6.2.4 |
| Legacy hash batch signing | `DirectorySignatureHelper.hashesMassiveSign`, `MassiveErrorCode` | §6.2.5 |
| Legacy item-by-item massive API | `MassiveSignatureHelper`, `MassiveSignConfiguration`, `MassiveType` | §6.2.6 |

### 13.6 Plugins / hash / certificate validation (§7)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| Plugin package format (single JAR, ServiceLoader, `plugin.json`) | `PluginLoader`, `PluginInfoLoader`, `AfirmaPlugin`, `PluginInfo`, `MinimalPluginInfo` | Not reimplemented as dynamic loading; documented for migration (§7.1). |
| Plugin permissions (INSTALL, RESET, PRESIGN, POSTSIGN, BUTTONS, MENU, COMMANDS, INLINE_PROCESS) | `Permission`, `PermissionChecker`, `PermissionsDialog` | Keep as internal capability flags if hook seams are kept (§7.1.2). |
| Pre-sign / post-sign / reset hooks (GUI signing only) | `AfirmaPlugin.preSignProcess/postSignProcess/reset`, `SignPanelSignTask.pluginsPreProcess/PostProcess/Reset` | Internal no-op seams; no official consumer (§7.2.1). |
| Plugin buttons on input / single result / multi result / viewer screens | `PluginButton`, `PluginIntegrationWindow`, `PluginsUiComponentsBuilder`, `PluginGraphicButton`, `PluginButtonsContainer`, `SignPanel`, `SignDetailPanel`, `SignResultListPanel`, `VisorPanel` | Data contracts `InputData`/`OutputData` (§7.2.2); used by built-in cert validation button. |
| Plugin menus in main menu bar | `GenericMenuOption`, `MainMenu.addSubMenus/doMenuAction`, `PluginLoader.getPluginAction` | Inserted between "Idioma" and "Ayuda" (§7.2.3); built-in "Huellas digitales" menu. |
| Plugin CLI commands + listing in general help | `PluginCommand`, `PluginCommandAction`, `CommandLineLauncher.getPluginCommand/processPluginCommand/buildGeneralSyntax` | `createdigest`/`checkdigest` become built-in (§7.2.4, §7.5.10). |
| Inline protocol processors + native response format `CERT\|SIGN[\|EXTRA]` | `SignDataProcessor`, `NativeSignDataProcessor`, `ProtocolInvocationLauncherSign.selectProcessor`, `ProtocolInvocationLauncherSignAndSave` | Only native format needed (§7.2.5). |
| Plugin configuration storage (java.util.prefs node per plugin package) | `PluginPreferences` (singleton bug), `PluginsPreferences`, `ConfigurationPanel`, `PluginConfigurationDialog` | Migrate hash prefs from `/es/gob/afirma/plugin/hash` (§7.2.7). |
| `UIFactory` services (wait dialog, dialog icon) | `UIFactory`, `CommonWaitDialog`, `DesktopUtil.getDefaultDialogsIcon` | Native equivalents (§7.2.6). |
| Plugins directory + `installed` registry file | `PluginsManager`, `SimpleAfirma.getPluginsDir`, `DesktopUtil.getAlternativeDirectory` | `%ALLUSERSPROFILE%\Autofirma\plugins`, `~/.afirma/Autofirma/plugins`, `~/Library/Application Support/Autofirma/plugins` (§7.3.1); read only for migration. |
| Plugin install / replace / uninstall flows, restart prompt | `PluginsManager.installPlugin/uninstallPlugin/forceRemove`, `PluginsManagementHandler`, `DesktopUtil.getResetApplicationCommand` | Drop (§7.3.3–7.3.6). |
| Plugin JAR signature check + signer confirmation | `JarVerifier`, `JarNoSignedException`, `CertificateConfirmPanel` | No trust anchors; drop (§7.3.3). |
| Plugin error codes 2302xx / 5300xx | `PluginManagerError`, `SimpleErrorCode`, `AOPluginException`, `PluginException`, `PluginInstalledException` | Message-key mismatch quirk (§7.3.5). |
| "Gestionar plugins" dialog (Ctrl/Cmd+G) | `PluginsManagementDialog`, `PluginsManagementPanel`, `MainMenu.showPlugingManagement` | Drop or replace with "Features" info (§7.4). |
| Hash plugin menu "Huellas digitales" (Fichero/Directorio × Calcular/Comprobar) | `HashPlugin`, `action/CalculateHashFileAction`, `CalculateHashDirAction`, `CheckHashFileAction`, `CheckHashDirAction` | Built-in menu (§7.5.1). |
| Single-file digest creation (hex+`h` / Base64 / binary; clipboard) | `CreateHashFileDialog`, `HashUtil`, `DigestManager`, `DigestManagerInputStream`, `HexUtils` | `.hexhash`, `.hashb64`, `.hash` byte-exact (§7.5.3, §7.5.6a). |
| Directory digest creation (recursive, skip list, parallel) | `CreateHashDirDialog`, `CreateHashAction` | OS-separator relative paths quirk; silent partial results on error (§7.5.4, §7.5.6b). |
| Directory digest documents XML `.hashfiles` / TXT `.txthashfiles` (CSV dead code) | `HashDocument`, `XmlHashDocument`, `TxtHashDocument`, `CsvHashDocument`, `HashDocumentFactory`, `schemas/folderhashes.xsd` | URL-safe Base64 `hash` + `hexhash` consistency check; broken format fallback (§7.5.5). |
| Single-file digest verification (format sniffing, algorithm by length) | `CheckHashFileDialog.checkHash/getHashAlgorithm` | Hex last-char stripping bug (§7.5.7). |
| Directory verification + `.hashreport` XML report | `CheckHashDirDialog.checkHash/generateXMLReport`, `CheckHashAction`, `HashReport`, `HashUIHelper.showSaveReportDialog`, `schemas/reportfolderhashes.xsd` | Report does not match its XSD (§7.5.8). |
| Hash preferences | `HashPreferences` | Keys `createHashAlgorithm`, `createHashFormat`, `createHashCopyToClipBoard`, `createHashDirectoryAlgorithm`, `createHashDirectoryRecursive` (§7.5.9). |
| CLI `createdigest` / `checkdigest` (options, help, exit codes, -gui flows) | `HashCommands`, `HashParameters`, `CreateHashCommand`, `CheckHashCommand`, `HashCommandException`, `HashUIHelper.createHashUI/checkHashUI` | Exit 0 even on mismatch; `-gui` always exit 0 (§7.5.10). |
| Windows Explorer context menus for digests | `HashPlugin.install/uninstall`, `registryInstallation/register.bat`, `unregister.bat`, `execute.bat`; `afirma-simple-plugin-hash-exe/*.vb` | Move to installer (HKCU/HKLM Classes), add `.txthashfiles`; Linux/macOS file-manager actions (§7.5.11). |
| Certificate validation button "Validar certificado de firma" | `ValidateCertsPlugin`, `ValidateCertAction`, `plugin.json` (validatecerts) | Built-in on single/multi result screens (§7.6.1). |
| Per-CA validation config (CRC issuer id, issuer cert pinning) | `CertificateVerifierFactory`, `validationfactory.properties`, `conf.properties.*`, bundled CA certs | Optional; formula documented; mostly expired CAs (§7.6.2). |
| OCSP validation | `OcspCertificateVerifier`, `OcspHelper` | AIA responder; unsigned request; response not verified (fix) (§7.6.3). |
| CRL validation (HTTP/HTTPS/FTP/LDAP/file) | `CrlCertificateVerifier`, `CrlHelper` | No freshness check (fix) (§7.6.3). |
| Validation result codes and messages | `ValidationResult`, `CertValidationMessages`, `certvalidationmessages.properties`, `messages.properties` | 12 results; UI mapping table (§7.6.1). |

### 13.7 Installers and configurator (§9)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| Configurator CLI (`-install`, `-uninstall`, `-keep_open`, `-headless`, `-jnlp`, `-firefox_roots`, `-certificate_path`, `-keystore_path`, `-config_path`, `-update_config`, `-language_path`, `-default_language`) and exit codes 0/-1 | `AutofirmaConfigurator`, `AutofirmaConfiguratorSilent` | §9.1.1. The Silent variant is used by the Windows exe and fixes `https:\\` in `-config_path`. |
| Configurator log file `AUTOFIRMA_CONFIGURATOR.afirma.log.xml` | `AutofirmaConfigurator*` static init, `LogManager` | Windows `%HOMEDRIVE%%HOMEPATH%\.afirma`; Linux `/var/tmp`; macOS `~/Library/Application Support/Autofirma`. |
| Configurator console output (graphical, I/O, stdout) | `ConsoleManager`, `GraphicConfiguratorConsole`, `IoConsole`, `PrintConsole`, `Console`, `ConsoleListener`, configurator `LookAndFeelManager` | Never graphical on Linux. Window titled "Configurador", 480×350. |
| Local CA and SSL certificate generation | `CertUtil` (configurator) | RSA-2048, SHA256withRSA, 10 years, `CN=Autofirma ROOT` / `CN=127.0.0.1`, SAN IP+DNS 127.0.0.1 and localhost, random 32-bit serial (may be negative). |
| SSL keystore and CA files (`autofirma.pfx` pwd `654321` alias `SocketAutoFirma`, `Autofirma_ROOT.cer`, macOS `autofirma.cer`) | `CertUtil.CertPack`, `ConfiguratorUtil.CERT_ALIAS`, `SecureSocketUtils` (runtime lookup) | Lookup: app dir, then alternative dir. |
| Admin-supplied certificate and keystore (Windows) | `ConfiguratorWindows` (`-certificate_path`/`-keystore_path`), MSI `CERTIFICATE_PATH`/`KEYSTORE_PATH` | Both are required; copied into the app dir. |
| Windows CA install into LocalMachine ROOT and removal of old "AutoFirma ROOT"-issued certificates | NSIS `AddCertificateToStore`, `DeleteCertificateOnInstall`, `un.DeleteCertificate` (crypt32) | Done by the installer, not the configurator. |
| Windows JNLP CA install into CurrentUser Root | `ConfiguratorWindows.importCARootOnWindowsKeyStore` (SunMSCAPI `Windows-ROOT`) | Legacy. |
| Firefox NSS CA install/uninstall on Windows (bundled certutil, one profile per user, master-password prompt, 3 delete retries) | `ConfiguratorFirefoxWindows`, `NSPreferences`/`ProfilesIni` (keystores-mozilla), `certutil.windows.zip` | Trust `C,,`; nicknames `SocketAutoFirma` and `Autofirma ROOT`. |
| Firefox `user.js` `security.enterprise_roots.enabled` | `ConfiguratorFirefoxWindows.configureUseSystemTrustStore`, `ConfiguratorFirefoxMac.configureUseSystemTrustStore` | Windows and macOS only. Driven by the checkbox, `-firefox_roots`, or the macOS dialog. |
| Windows system PATH add/remove | `WindowsCmdExecutor`, `windows/autofirma-addpath.cmd`, `windows/autofirma-removepath.cmd` | `HKLM\…\Session Manager\Environment\Path` REG_EXPAND_SZ, 10 s timeout, no broadcast. |
| Windows interactive EXE installer (pages, integration checkboxes, JRE component, version check, old-version removal with HKCU prefs backup, shortcuts, ARP keys, `HKLM\SOFTWARE\Autofirma`) | `Autofirma_NSIS_project_EXE_{32,64}.nsi`, `lang_strings.nsh`, `Registry.nsh`, `nsProcess` | §9.3.2–9.3.3. |
| Windows shell integration: `HKCR\*\shell\afirma.sign` ("Firmar con Autofirma" → `sign -gui -i "%1"`), `.csig`/`.xsig` Verify (`verify -gui -i "%1"`), `HKCR\afirma` URL protocol | NSIS EXE and MSI scripts | Command paths are unquoted (gotcha). |
| Windows uninstaller | NSIS `Section "uninstall"`, `un.UninstallFromRegistry`, configurator `-uninstall` | Removes the HKCU Java prefs tree. Leaves `.csig`/`.xsig` roots behind. |
| MSI deployment and public properties (`CREATE_ICON`, `FIREFOX_SECURITY_ROOTS`, `CERTIFICATE_PATH`, `KEYSTORE_PATH`, `CONFIG_PATH`, `UPDATE_CONFIG`, `USE_SYSTEM_JRE`, `DEFAULT_LANGUAGE`, `LANGUAGE_PATH`) | `Autofirma_{32,64}_installer.wxs`, `Autofirma_NSIS_project_MSI_{32,64}.nsi` (`AutofirmaGenerator.exe`), `no_ejecutar_*.exe`, `forceUninstallFromReg.bat` | UpgradeCode `{A6D90EBF-E089-4281-9269-AE5D20BA74D2}`; custom actions run as SYSTEM. |
| Windows launchers and JVM options, splash, elevation manifest | `Autofirma_launch4J_*.xml`, `AutofirmaCommandLine_launch4J_*.xml`, `AutofirmaConfigurator.manifest`, `splash.bmp` | No single-instance mutex. Configurator uses `highestAvailable`. |
| Bundled JRE, Access Bridge, extra trusted CAs in cacerts | `java{32,64}/jre`, `jre/conf/accessibility.properties`, `certificados/insert_cacerts.{bat,sh}` | Spanish TSP roots (FNMT, ACCV, Izenpe, ACA, CATCert, ANF, EADtrust, Firma Profesional, Logalty, USERTrust). |
| Debian package (control deps, launcher, `afirma.desktop` with `x-scheme-handler/afirma`, metainfo, Firefox prefs `AutoFirma.js`, preinst/postinst/prerm/postrm) | `linux/instalador_deb/src/**` | CA goes to `/usr/local/share/ca-certificates` + `update-ca-certificates`. The deb never calls configurator `-uninstall`. |
| RPM packages (Fedora/SUSE): `%pre/%post/%preun/%postun`, mimeapps.list registration, Firefox prefs | `linux/instalador_rpm_{fedora,suse}/rpmbuild/SPECS/autofirma.spec` | No system CA install. Lowercase `%{_libdir}/autofirma`. |
| Linux configurator: user enumeration from `/etc/passwd`, generation of `script.sh`/`uninstall.sh` with certutil commands for Firefox (classic/snap) and Chrome/Chromium NSS DBs, skipping uninitialised DBs | `ConfiguratorLinux`, `ConfiguratorFirefoxLinux`, `certutil.linux.zip` | Firefox `C,,`, `.pki/nssdb` `TCP,TCP,TCP`. Flatpak and XDG Firefox are not handled. |
| macOS package and postinstall (locale detection, run configurator as root) | `macos/Autofirma_Packages_*/Autofirma.pkgproj`, `scripts/postinstall` | Identifier `es.gob.afirma`, payload `/Applications/Autofirma.app`. No uninstaller pkg. |
| macOS launcher app (afirma: URL via `kAEGetURL`, JVM args, `LSUIElement`, Help Book) | `macos/Lanzador/**` (`AppDelegate.m`, `Info.plist`) | Bundle id `es.gob.afirma.simpleafirma.osx`. No document types. |
| macOS keychain trust (CA `trustRoot`, leaf `trustAsRoot` in System.keychain), old-certificate removal by CN/hash, keychain password handling | `ConfiguratorMacOSX` | Uses `sudo -S security …` and osascript admin. |
| macOS Firefox NSS install/uninstall and NSS lib symlinks | `ConfiguratorFirefoxMac`, `MozillaKeyStoreUtilitiesOsX.configureMacNSS`, `ShellScript`, `certutil.osx.zip`, `macos/nss/*.dylib` | Scripts run with administrator privileges via osascript. |
| Configurator uninstall (plugins, alternative dir, system prefs) | `Configurator*.uninstall`, `PluginsManager`, `PreferencesManager.removeSystemPrefs`, `KeyStorePreferencesManager.removeSystemPrefs` | Windows/RPM run automatically; macOS manual; Debian never. |
| Install-time config file import and daily auto-update | `ConfigUpdaterManager`, `ConfigDataInfo` (SHA-256), `PreferencesManager` internal node (`configFileUrl`, `configFileSHA256`, `allowUpdateConfig`, `configDate`) | `YYYYMMdd` week-year gotcha. |
| Language pack install and default language at install time | `LanguageManager.addLanguage`, `PreferencesManager.PREFERENCES_LOCALE` (`default.locale`), `DirectoryUtil.getLanguagesDir` | `<alternativeDir>/languages/<xx_YY>`. |
| Unused legacy macOS trust template | `afirma-simple/src/main/resources/osx/trust_settings.plist` | Not referenced by code. |
| Legacy installers (not to port) | `afirma-standalone-installer/StandAlone.nsi`, `afirma-windows-store/**` | Obsolete. |

### 13.8 Restore configuration (§10)

| Feature | Java class(es) / file(s) | Notes |
|---|---|---|
| Restore installation menu entry (Herramientas > Restaurar instalación, Ctrl/Cmd+R) | `ui/MainMenu` (`showRestoreConfig`) | Modal dialog. Available on all OSes; does nothing on unsupported OSes |
| Restore dialog: intro text, console log area, Firefox enterprise-roots checkbox (Win/macOS only), Iniciar/Cerrar buttons, Esc closes (not macOS) | `ui/restoreconfig/RestoreConfigDialog`, `RestoreConfigPanel` | Runs on a background thread. The button is never really disabled (quirk). The checkbox defaults to unchecked, which writes `false` |
| OS dispatcher and start/end console lines | `RestoreConfigManager`, `RestoreConfig` | Prints `INFO: Inicio/Fin de la restauración` |
| Local CA + SSL cert regeneration (RSA 2048, SHA256withRSA, 10 years, CN=Autofirma ROOT / CN=127.0.0.1, SAN IP only) | `ui/restoreconfig/CertUtil` | Differs from the configurator, which adds DNS:localhost (and DNS:127.0.0.1). Serial may be negative |
| Cert artefacts: `autofirma.pfx` (pwd `654321`, alias `SocketAutoFirma`), `Autofirma_ROOT.cer`, macOS `autofirma.cer` | `RestoreConfigWindows/Linux/MacOSX`, `CertFilesInfo` | Reused if present (no expiry check). Alternative dirs: `%ALLUSERSPROFILE%\Autofirma`, `~/.afirma/Autofirma`, `~/Library/Application Support/Autofirma` |
| Windows: install CA in current-user ROOT store as "Autofirma ROOT" (delete old, retry dialog) | `RestoreConfigWindows.installRootCAWindowsKeystore` | SunMSCAPI `Windows-ROOT`. Windows shows its own confirmation dialogs |
| Windows: Firefox NSS install for all users' profiles via bundled certutil (`-t "C,,"`), with prior delete | `RestoreConfigWindows`, `RestoreConfigFirefox` | `certutil.windows.zip` extracted to `<workingDir>\certutil` then removed. 5 s timeout. Any output = error |
| Windows: `afirma://` protocol in HKCR (direct write, else UAC-elevated bat fallback) | `RestoreConfigWindows.restoreProtocolRegistry`, `/windows/afirma_register.bat`, `/windows/execute.bat` | Bat only adds missing keys. The command value is unquoted (quirk) |
| Windows/macOS: Firefox `security.enterprise_roots.enabled` in each profile's `user.js` | `RestoreConfigFirefox.configureUseSystemTrustStore`, `RestoreConfigFirefoxMacOS.configureUseSystemTrustStore` | Creates or edits `user.js` (CRLF, UTF-8). On macOS chowns the file via osascript admin if needed |
| "Close Firefox/Chrome" blocking prompt loops | `RestoreConfigWindows/Linux/MacOSX.closeFirefox`, `RestoreConfigLinux.closeChrome` | tasklist / `ps -aux` / `ps aux` substring checks. Cancel continues with a warning |
| Linux: Chrome/Chromium user NSS DB trust (`~/.pki/nssdb`, `~/snap/chromium/current/.pki/nssdb`, `-t "TCP,TCP,TCP"`) | `RestoreConfigLinux`, `RestoreConfigFirefox.installRootCAChromeKeyStore` | System `certutil` via generated install/uninstall scripts. No flatpak |
| Linux: Firefox NSS install (`~/.mozilla/firefox`, `~/snap/firefox/common/.mozilla/firefox`) | `RestoreConfigFirefox.installRootCAMozillaKeyStore(…, usersDirs)` | Root detection bug: only the current user's home is processed |
| Linux: Firefox protocol prefs copied to `<libpath>/firefox/defaults/pref` and `/etc/firefox/pref` via `pkexec` script | `RestoreConfigLinux.restoreProtocolHandler` | BROKEN: resource `/linux/autofirma.js` is missing, so the step always fails. Intended content = installer `AutoFirma.js` |
| macOS: chown app support dir, keychain password prompt, remove old certs, add-trusted-cert (trustRoot CA, trustAsRoot SSL) into System.keychain | `RestoreConfigMacOSX`, `so/macos/ShellScript`, `so/macos/UnixUtils` | Uses `sudo -S` fed with the keychain/user password, and osascript admin. Cancel aborts the thread |
| macOS: Firefox NSS reinstall per profile with bundled certutil (`certutil.osx.zip`) | `RestoreConfigFirefoxMacOS` | Profiles only from `~/Library/Application Support/firefox/profiles.ini`. The delete loop's grep never matches (quirk) |
| Dead/unused: Chrome "Local State" excluded_schemes sed scripts, `Console` interface, `osx/trust_settings.plist`, several message keys | `RestoreConfigFirefox.removeAppExecutionWarningInChrome`, `Console`, resources | Do not reimplement |


