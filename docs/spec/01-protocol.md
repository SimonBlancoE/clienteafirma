# 01 — Browser invocation protocol and web integration

> **Purpose.** Normative description of everything that travels between a web page (AutoScript JS), the native
> AutoFirma application, the intermediate "storage/retriever" servlets and the three‑phase ("trifásica") / batch
> signing servers. A Rust developer must be able to re‑implement the **native application side** byte‑compatible
> with the Java implementation, and talk to the existing JS and servers, **without reading the Java code**.
>
> **Source baseline.** Repository `/home/octo/Projects/autofirma`, commit `0d7f3cf01` (Maven version `1.9.1`).
> At run time AutoFirma reports version text **`1.10`** (`afirma-simple/src/main/resources/properties/updater.properties`,
> key `currentVersionText.<OS>`; numeric build `21`) — this is the value compared with `mcv`. AutoScript
> **`1.10.1`** (`AutoScript.VERSION`), JS version code **`4`** (`jvc=4`), protocol version **`4`** (sent) which the
> app upgrades to **`4.1`**.
>
> **Sibling specs.** Base64, `Properties`, HTTP client and the generic exception model are specified in
> `07-core.md` (§7, §9, §10); signature formats in the format specs (e.g. `02-cms-cades.md`); dialogs, CLI and
> installer (including generation of `autofirma.pfx`) in `06-app-ui-cli-installer.md`. This document only repeats
> what is needed to implement the wire protocol.
>
> **Conventions.**
> * "App" = the native application (what is being re‑implemented). "Page"/"JS" = `autoscript.js`. "Storage" =
>   `afirma-signature-storage` `StorageService`; "Retriever" = `afirma-signature-retriever` `RetrieveService`.
> * `code` = exact bytes/strings. All strings are ASCII unless stated. `\n` = LF.
> * **⚠ QUIRK** marks Java behaviour that is surprising or buggy but observable on the wire; a byte‑compatible
>   implementation must reproduce it unless the item says "MAY fix". **⚠ AMBIGUOUS** marks things the code does
>   not settle.
> * Java class names are given so the parity checklist (§14) can be traced; they are not needed to implement.

---

## Table of contents

1. Overview of invocation modes
2. Common encoding primitives (URL parsing, Base64, properties, keystore, URL validation, ids, booleans)
3. Operation catalogue: `afirma://` URL grammar and parameters
4. Envelopes for indirect requests (`fileid` → XML / JSON parameter lists)
5. Transports: WebSocket server, legacy local HTTPS "service" socket, direct launch + intermediate server
6. Intermediate server (Storage / Retriever) wire specification
7. Responses, result formats and error codes
8. Cipher specification (DES legacy and AES)
9. Batch signing (JSON and XML), client side
10. Three‑phase (trifásica) signing client protocol
11. Protocol versions and compatibility
12. OS‑specific behaviour, sticky signatory, keystore selection, locale, logs, misc
13. Consolidated list of quirks / ambiguities
14. Parity checklist
- Appendix A — complete AutoFirma error code table (`AFnnnnnn`)
- Appendix B — legacy `SAF_nn` table
- Appendix C — AutoScript (`ASnnnnnn`) error codes and JS‑side mapping

---

## 1. Overview of invocation modes

The page never talks to the app directly at first: it asks the **operating system** to open a URL with the custom
scheme `afirma:` (Windows registry `HKCR\afirma` → `Autofirma.exe "%1"`; Linux `.desktop`
`MimeType=x-scheme-handler/afirma;` `Exec=/usr/bin/autofirma %u`; macOS a native launcher bundle registered in
`Info.plist` `CFBundleURLSchemes=afirma`). The app is started with the URL as `argv[0]` (**one new process per
URL**). What happens next depends on the transport chosen once per page load by `cargarAppAfirma()`:

```
                         ┌──────────────────────── Web page: autoscript.js 1.10.1 ─────────────────────────┐
                         │ cargarAppAfirma(): picks ONE client per page load (no fallback afterwards)       │
                         └───────┬──────────────────────────────┬────────────────────────────────┬─────────┘
          (A) WebSocket          │   (B) Local HTTPS "service"   │   (C) Intermediate server       │
          desktop default        │   IE11 / Firefox<=60 / no WS  │   iOS, Android, setForceWSMode, │
                                 │   (⚠ broken with v=4, §11)    │   IE<=10, Safari 10             │
   OS launch URL                 ▼                               ▼                                 ▼
   afirma://websocket?ports=P1,P2,P3&v=4&jvc=4&idsession=ID      afirma://service?ports=..&v=4&jvc=4&idsession=ID
                                                                                   afirma://<op>?jvc=4&<op params>&ver=4&op=<op>&id=RID
                                                                                          &appname=..&key=DES8[&cipher=..]&stservlet=..[&aw=true]
                                                                                   or, if that URL > 2000 chars, after uploading the params:
                                                                                   afirma://<op>?jvc=4&fileid=FID&rid=RID&rtservlet=..&stservlet=..&key=..[&cipher=..]
   App side:
   - wss server on first free port   - TLS server socket on first      - (if fileid) fetch params from Retriever, decrypt
     of P1..Pn, 0.0.0.0, TLS           free port, raw HTTP             - (if aw=true) PUT "#WAIT" every 10 s to Storage
   - page sends "echo=-idsession=ID@EOF", - page POSTs /afirma bodies:   - run the operation (UI)
     app answers "OK"                    echo/cmd/fragment/firm/send  - PUT result (encrypted) to Storage, exit
   - page sends "afirma://<op>?..."   - reply: HTTP 200, body b64url  Page polls Retriever "op=get&v=1_0&id=RID&it=n"
     as ONE text frame                   (result split in 1 MB parts)  every 3 s (4 s mobile) until data appears
   - app answers "#wait"; page sends  - app exits after 90 s idle
     "getresult?idsession=ID" every 2 s
     until the result frame arrives
   - app exits when the page closes
     the socket (or 30 s w/o 1st msg)
```

| Mode | Chosen by the page when | Launch URL | Request channel | Response channel | App lifetime |
|---|---|---|---|---|---|
| (A) WebSocket | `"WebSocket" in window` and not IE and not Firefox ≤ 60, and not mobile/forced | `afirma://websocket?…` | WSS text frames to `wss://127.0.0.1:<port>` | same socket | until socket closed by client, or 30 s without first message |
| (B) Service socket | not (A), not IE ≤ 10, not Safari 10, not mobile/forced | `afirma://service?…` | HTTPS POST `https://127.0.0.1:<port>/afirma` (raw HTTP over TLS) | HTTP response bodies | until 90 s of inactivity (`Runtime.halt(0)`) |
| (C) Intermediate server | iOS, Android, `setForceWSMode(true)`, IE ≤ 10, Safari 10 | `afirma://<op>?…` (or `intent://…` on Chrome/Android) | URL itself, or Retriever (if `fileid`) | Storage servlet `op=put`, polled by the page from Retriever | exits after the single operation |

The app also accepts the operation URLs (`afirma://sign?…`, …) as **messages** inside (A) and (B); in that case
results are returned on the socket instead of the Storage servlet ("bySocket" mode, see §3.0).

Java entry points: `SimpleAfirma.main` (argv[0] starts with `afirma://`, compared lower‑case) →
`ProtocolInvocationLauncher.launch(url)` = `launch(url, protocolVersion=null, bySocket=false)`. For socket
messages the servers call `launch(message, <version>, bySocket=true)`.

---

## 2. Common encoding primitives

### 2.1 Query‑string parsing (app side)

Used for every `afirma://` URL and every socket message (`ProtocolInvocationLauncher.extractParams`, identical in
effect to `ProtocolInvocationUriParser.parserUri`):

1. Take everything after the **first** `?` (if there is no `?`, the whole string is used — it then contains no
   usable pair and is ignored).
2. Split on every `&` (Java `String.split("&")`: trailing empty items dropped).
3. For each item, `eq = indexOf('=')`. If `eq <= 0` the item is **ignored** (no key, or no `=`).
4. Key = `item[0..eq]` **not decoded**, case‑sensitive. Value = `URLDecoder.decode(item[eq+1..], "UTF-8")`:
   * `+` → space (**⚠ QUIRK**: a raw standard‑Base64 `+` becomes a space; see §2.2, 2.3).
   * `%HH` → byte; byte sequence decoded as UTF‑8.
   * A malformed `%` escape throws `IllegalArgumentException`, which is **not caught** by `launch()`
     (**⚠ QUIRK**): direct launch → caught by the global handler of `main` (logged; exit status −1 only for
     `afirma://websocket` URLs, otherwise no result is produced); synchronous WebSocket → no reply frame;
     asynchronous WebSocket → the page waits forever (§5.1.3); service socket → reply 401200. Recommended Rust
     behaviour: treat it as a parameter error of the operation; document the deviation.
   * Empty value (`k=`) → `""` (parserUri explicitly; extractParams via decode of empty string).
5. Duplicate keys: **last occurrence wins** (HashMap put).
6. The operation is taken from the authority/path: text between `://` and `?` (or end), a trailing `/` removed,
   cut at the first `/`. Dispatch in `launch()` is done with **case‑sensitive prefix tests** on the raw URL, each
   operation accepting two spellings: `afirma://<op>?` and `afirma://<op>/?` (e.g. `afirma://sign/?…`).
   `afirma://SIGN?…` is *not* recognised (→ unsupported operation).
7. Additionally an `op` query parameter is present in every URL built by AutoScript (`op=sign`, …). It is what the
   sign launcher uses to decide sign/cosign/countersign (see §3.4). `signandsave` uses `cop` instead.

Values inside the XML/JSON envelopes (§4) are also passed through `URLDecoder.decode` (same `+`→space quirk).

### 2.2 Base64 (Java `es.gob.afirma.core.misc.Base64`)

**Encoding** (`encode(bytes)` / `encode(bytes, urlSafe=true)`):
* RFC 4648 alphabet, standard (`+/`) or URL‑safe (`-_`). **Padding `=` is always emitted in both variants.**
  No line breaks.

**Decoding** (`decode(String)`; there is a `decode(str, urlSafe)` but protocol code always uses the standard
decoder after manually replacing `-`→`+` and `_`→`/`):
* Characters TAB, LF, CR and SPACE are **skipped** anywhere.
* `=` is accepted; when a 4‑char quartet containing `=` is completed, decoding **stops** (anything after is ignored).
* Any other non‑alphabet character (including `-`, `_`, `.`, `%`) → `IOException("Bad Base64 input character …")`
  *when the standard decoder is used without normalisation*.
* A trailing incomplete quartet (1–3 significant chars, i.e. unpadded input whose length is not a multiple of 4)
  is **silently dropped** (⚠ QUIRK: unpadded Base64 loses its last 1–2 bytes).
* Input of length 1–3 → `IllegalArgumentException` (not `IOException`); length 0 → empty array.

**`isBase64(text)`** (used to decide whether `dat` is Base64): every char must be in
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=_-\t\n+/0123456789\r~`; `=` may only appear in the last two
positions; count of characters excluding `\n` and `\r` must be a multiple of 4. (Space is **not** allowed, `~` is.)

Normalisation used almost everywhere on the app side before decoding: `s.replace("_", "/").replace("-", "+")`.

### 2.3 The `dat` parameter (data to sign / save) — `DataDownloader.downloadData(dat, gzip)`

Evaluated in `UrlParameters.setCommonParameters` (every data operation; for `load` the result is unused):

1. If `dat` starts with `file:/` (case‑sensitive, before trimming) → error **600117**
   `RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL` ("No se permite la lectura de ficheros locales").
2. If `gzip=true` (`Boolean.parseBoolean`) **and** `isBase64(dat)` → `gunzip(Base64.decode(normalise(dat)))`
   (GZIP member format, `java.util.zip.GZIPInputStream`). If `gzip=true` but not Base64, continue below.
3. `s = dat.trim()`.
4. If `s` starts with `http://` or `https://` → the app **downloads** the data with an HTTP **GET** (normal TLS
   validation + Autofirma trust settings, §12.6). ⚠ QUIRK/security: any reachable URL is fetched (SSRF‑like);
   `localhost` is *not* blocked here.
5. If `s` starts with `ftp://` → downloaded via FTP (Java `URL.openStream`).
6. If `s` starts with `file:/` → (unreachable because of step 1).
7. If `isBase64(s)` → `Base64.decode(normalise(s))`; if that throws, fall through.
8. Otherwise the raw bytes of `s` in the platform default charset (⚠ AMBIGUOUS: JVM default, UTF‑8 on modern JDKs).

Any exception in steps 2–8 → error **200102** `LOADING_LOCAL_FILE_ERROR` (message prefix
`"No se han podido obtener los datos: "`).

AutoScript always sends URL‑safe Base64 with `=` padding for `dat` (WebSocket: raw, not percent‑encoded; service
and server modes: percent‑encoded). In server mode it also strips `\r` and `\n`. If the page's data is an
`http(s)://` URL the socket/server clients pass it untouched; the WebSocket client mangles it (`/`→`_`) — see
§13 (AutoScript bugs).

### 2.4 The `properties` parameter (extraParams)

* Value: Base64 (either alphabet; normalised `-`→`+`, `_`→`/`) of a **Java `.properties` text** encoded UTF‑8.
* Parsed with Java `Properties.load(Reader)` semantics: lines `key=value` or `key:value` or `key value`;
  `#`/`!` comment lines; leading whitespace ignored; backslash escapes (`\n`, `\t`, `\\`, `\uXXXX`, line
  continuation with trailing `\`). A Rust implementation must implement this grammar exactly (extra params often
  contain `\n` escapes, e.g. `layer2Text`).
* Empty or absent → empty map. **Decoding/parsing failure is not an error**: it is logged and an **empty** map is
  used.
* AutoScript produces it from the page's `params` string (`Base64.encode(params)`; note the JS encoder converts
  `\r\n`→`\n` and encodes non‑BMP characters as CESU‑8 — §13).
* Extra params that the protocol layer itself interprets (all others are passed to the signers and are specified
  in the signer specs):

| Key | Used by | Meaning |
|---|---|---|
| `headless` | all | `true` → no progress dialogs; certificate selection mandatory‑automatic (see `mandatoryCertSelection`); no confirmation dialogs (operations that need user input fail). |
| `mandatoryCertSelection` | cert dialogs | `false` → auto‑select when exactly one certificate passes the filters (same as `headless=true` for selection). |
| `filter`, `filters`, `filters.1`, `filters.2`, … | cert dialogs | certificate filters (`;`‑separated criteria; `filters.N` are OR‑ed). Includes `disableopeningexternalstores`. Semantics in the keystore/filters spec. |
| `checkSignatures` | sign, signandsave | `true` → validate existing signatures before multi‑signing (relaxed validation, may ask user). |
| `filenameExts`, `filenameDescription`, `filenameCurrentDir`, `filenameActualName` | sign, signandsave | file chooser when no data is supplied. Exts comma‑separated. |
| `filenameSaveExts`, `filenameSaveDescription`, `filenameSaveCurrentDir` | signandsave | save dialog. |
| `target` | countersign | `tree` → counter‑sign whole tree; anything else → leaves. |
| `mode` | sign (XAdES) | `explicit` + XAdES format (not `XAdEStri`, not `useManifest=true`) → data replaced by its SHA‑1 digest and `mimeType=hash/sha1` (deprecated "explicit XAdES"). |
| `profile` | sign | **removed** before signing (baseline profiles disabled). |
| `visibleSignature` (`want`/`optional`, case‑insensitive), `visibleAppearance` (`custom`) | formats `Adobe PDF`, `Adobe PDF TriPhase`, `PAdES`, `PAdEStri`, `ETSI.CAdES.detached`, `adbe.pkcs7.detached` (exact, case‑sensitive list) | show the visible‑signature area dialog. If the user cancels and `visibleSignature=want` and the area params (`signaturePositionOnPageLowerLeftX/Y`, `…UpperRightX/Y`, and `signaturePage` or `signaturePages`) are not all present → error **501010** `VISIBLE_SIGNATURE_IS_MANDATORY`. |
| `allowShadowAttack`, `pagesToCheckShadowAttack` | PAdES with `checkSignatures=true` | if `allowShadowAttack` is not `true` and `pagesToCheckShadowAttack` is absent, the app sets `pagesToCheckShadowAttack=10` before validating. |
| `expPolicy` etc. | all signers | expanded by `ExtraParamsProcessor.expandProperties` (policy presets); incompatibility → error 501008. |

### 2.5 Keystore selection parameters `ksb64` / `keystore`

* `keystore` (legacy, plain text) takes precedence over `ksb64` if both present.
* `ksb64` = **standard** Base64 of the text, decoded with `Base64.decode` *without* URL‑safe normalisation
  (⚠ QUIRK: a URL‑safe value containing `-`/`_` fails to decode → silently treated as "no keystore").
  Decode failure → no keystore (no error).
* Text format (decoded with the platform charset): `NAME` or `NAME:LIBRARY_PATH`. Name = the whole value when
  there is no `:` (not trimmed), else the text before the first `:` trimmed (the 1‑character value `:` yields no
  name). Library = text after the first `:` (only if non‑empty), trimmed, all `"` and `'` removed, then
  canonicalised as an absolute file path; invalid path → no library.
* Name resolution (`SimpleKeyStoreManager.getKeyStore(name, invokedFromBrowser=true)`), first match wins:
  1. case‑insensitive match against the keystore **display names** below;
  2. names of PKCS#11 smart cards registered by the user/system in the app preferences (→ PKCS#11 with that lib);
  3. exact (case‑sensitive) enum constant name.
  `MOZ_UNI` is always replaced by `MOZ_UNI_WITH_OS` (Firefox store + OS store) when invoked from a browser.
  Unknown → `null` → OS default store.

| Enum constant (what AutoScript sends) | Display name (also accepted) |
|---|---|
| `WINDOWS` | `Windows` |
| `APPLE` | `Llavero de Mac` |
| `SHARED_NSS` | `NSS` |
| `PKCS12` | `PKCS#12 / PFX` |
| `JAVA` | `Java KeyStore / JKS` |
| `PKCS11` | `PKCS#11` |
| `SINGLE` | `PKCS#7 / X.509` |
| `MOZ_UNI` | `Mozilla / Firefox (unificado)` |
| `MOZ_UNI_WITH_OS` | `Mozilla / Firefox (unificado) junto a almacen de SO` |
| `JCEKS` | `Java Cryptography Extension KeyStore (JCEKS)` |
| `JAVACE` | `Java KeyStore / JKS (Case Exact)` |
| `TEMD` | `TEMD (Tarjeta del Ministerio de Defensa)` |
| `WINADDRESSBOOK` | `Windows / Internet Explorer (otras personas / libreta de direcciones)` |
| `WINCA` | `Windows / Internet Explorer (CA intermedias)` |
| `CERES` | `Tarjeta FNMT-RCM CERES` |
| `DNIEJAVA` | `DNIe y tarjetas FNMT-TIF` |
| `KNOWN_SMARTCARDS` | `Tarjetas inteligentes conocidas mediante PKCS#11` |
| `SMARTCAFE` | `G&D SmartCafe con Applet PKCS#15` |
| `CERES_430` | `Tarjeta FNMT-RCM CERES 4.30 o superior` |

AutoScript defaults: `MOZ_UNI` when the browser is Firefox, otherwise none (OS store). The precedence between
this parameter and user preferences is in §12.3.

### 2.6 Servlet/service URL validation (`validateURL`)

Applied to `rtservlet`, `stservlet`, `batchpresignerurl`, `batchpostsignerurl`:

1. `URLDecoder.decode(value, UTF‑8)` **again** (the value was already decoded once by the query parser → double
   decoding; `+` → space twice‑over). Then parsed as a URL; parse failure → "invalid" error.
2. Scheme must be exactly `http` or `https` (else "invalid").
3. Host equal to `localhost` or `127.0.0.1` (exact string compare; `[::1]`, `127.0.0.2`, `LOCALHOST` pass!) →
   "local" error.
4. The full URL string must not contain `?` nor `=` → "invalid" ("Se han encontrado parametros en la URL del servlet").

The URL is used **as given** (path included) as the endpoint; the app appends its own `?op=…` query.

### 2.7 Identifiers

* **Operation/session id** (`id`, falling back to `fileid` when `id` is absent): length ≤ **20**; every char, after
  `toLowerCase(Locale.ENGLISH)`, in `a–z` or `0–9` (ASCII). Violation → op‑specific "invalid session id" error
  (600120 sign/signandsave, 600201 selectcert, 600303 save, 600410 batch). It is used as the Storage file name.
  Empty string is accepted.
* **WebSocket/service `idsession`** (launch URL): accepted if every char satisfies Java
  `Character.isLetterOrDigit` (Unicode letters/digits!). If invalid (or empty/absent) the app logs it and runs
  **without** session id, i.e. **no session check at all** (⚠ QUIRK/security). AutoScript generates 20 chars from
  `1234567890abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` (61 symbols — lowercase `v` missing).
* **`ports`**: comma‑separated decimal integers; each parsed with `Integer.parseInt` and **absolute value** taken
  (`-8080` → 8080). A non‑numeric item throws `IllegalArgumentException`, not caught by `launch()` → global
  handler in `main`: WebSocket launch exits with status −1; service launch produces nothing (⚠ QUIRK).

### 2.8 Booleans and numbers

* Booleans use Java `Boolean.parseBoolean`: `true` iff the value equals `"true"` ignoring case; anything else
  (including absent) is `false`.
* `servicetimeout`: `Integer.parseInt` (milliseconds, HTTP read timeout for triphase/batch services). Negative
  values are ignored (default). Non‑numeric → error **600009** (⚠ QUIRK: wrong code reused,
  `UNSUPPORTED_CIPHER_KEY`, message "El valor del parametro del tiempo de espera de lectura de los servicios no es
  valido").
* `jvc`: `Integer.parseInt`; absent/invalid → `1`.
* Protocol version strings (`v`, `ver`): `"X"` or `"X.Y"` (unsigned decimal ints; `X.Y` split at the first `.`);
  `v` is trimmed. Invalid/absent → version **0**. Rendered as `X` when `Y=0`, else `X.Y`.
* `mcv` (minimum client version): free text compared against the app version text `1.10` with the
  algorithm in §11.4. Malformed text (non numeric parts) → runtime exception → generic error of the operation.

---

## 3. Operation catalogue: `afirma://` URL grammar and parameters

### 3.0 Grammar, contexts and dispatch

```
invocation   = "afirma://" op-name [ "/" ] "?" query          ; op dispatch is a case-sensitive prefix test
op-name      = "websocket" / "service"                        ; channel openers (launch URL only)
             / "sign" / "cosign" / "countersign"
             / "signandsave" / "selectcert" / "batch" / "save" / "load"
query        = pair *( "&" pair )                             ; §2.1
socket-only  = "echo=" ...                                    ; WebSocket / service handshake (§5)
             / "getresult?" ...                               ; WebSocket async polling (§5.1.3)
```

* Any input not starting with `afirma://` (or `getresult?`) → error **620009** `UNSUPPORTED_REQUEST_SCHEME`
  (legacy `SAF_02`). A null URL → **620012** (`SAF_01`). Unknown op → **600002** `UNSUPPORTED_OPERATION`
  (`SAF_04`). In all three cases an error dialog is shown and the error string is returned/sent (§7.2).
* There are **no** other operations: in particular no `websave`, `getversion`, `echo`/`version` or log‑retrieval
  operation exists in either the app or AutoScript (searched the whole repository). Version information only
  travels in `v`/`ver`/`jvc`/`mcv` (§11).
* `getresult?…` (it passes the scheme check) received outside the async WebSocket handler → unknown op (600002).
  The scheme test is case‑sensitive (`AFIRMA://…` → 620009) although `main` recognises the URL case‑insensitively.
* **Execution context** (`bySocket`): `true` when the URL arrived as a WebSocket/service message, `false` for a
  direct OS launch (intermediate‑server mode). In the code this is `servicesRequired = !bySocket` and controls
  whether `stservlet` is validated and whether the result is uploaded to Storage.
* When the request arrives on a socket, the protocol version is the one negotiated at channel opening (`v` of the
  `websocket`/`service` URL, possibly upgraded to 4.1); the `ver` parameter of the operation is **ignored**.
  For direct launch the version is taken from `ver` (§11).
* Before parameter parsing: `jvc` is read (int, default 1); if `jvc < 1` a warning dialog
  ("Versión de JavaScript no segura") is shown and processing continues.
* The process‑level parameter `dlgload` (only read from **argv[0]**, i.e. the launch URL): `false` disables the
  app's "progress" pop‑ups for the whole process.

### 3.1 Parameters common to all data operations (`UrlParameters.setCommonParameters`)

Processed for `sign`, `cosign`, `countersign`, `signandsave`, `selectcert`, `batch`, `save`, `load`, **in this
order** (first failure wins):

| # | Param | Type / encoding | Meaning | Validation → error |
|---|---|---|---|---|
| 1 | `cipher` | Base64 (either alphabet) of a JSON cipher config (§8) | AES config for intermediate‑server data | Base64 decode `IOException` → **600009** "El JSON para la clave de cifrado no esta formado correctamente". (Value of 1–3 chars → uncaught `IllegalArgumentException` → operation's generic error.) JSON validity is **not** checked here. If `key` is also present and valid, the decoded JSON text has its **last character removed** and `,legacydes:"<key>"}` appended (assumes the JSON ends with `}`; text decoded with platform charset). |
| 1b | `key` | 8 characters (AutoScript: 8 decimal digits) | DES key (legacy cipher) | Present and non‑empty with length ≠ 8 → **600009** "La longitud de la clave de cifrado no es correcta". Empty value → no cipher. Without `cipher`, a valid key yields the cipher config bytes `{algo:"DES", key:"<key>"}` (exactly this text, note unquoted names and the space). |
| 2 | `aw` | boolean | "active waiting": app must post `#WAIT` keep‑alives to Storage (§6.4) — only honoured in direct‑launch mode | — |
| 3 | `mcv` | version text | minimum AutoFirma version required (checked later, §11.4) | — |
| 4 | `servicetimeout` | decimal int, ms | HTTP read timeout for triphase/batch servers (only applied if ≥ 0) | non‑numeric → **600009** (sic) |
| 5 | `dat` | §2.3 | input data | `file:/…` → **600117**; fetch/decode failure → **200102** |
| 5' | `fileid` | id (§2.7) | only if `dat` absent: the real parameters must be downloaded from Retriever (§4) | — |
| 5'' | `rtservlet` | URL (§2.6) | Retriever endpoint; required when `fileid` is used | missing → **600101**; local host → **600010**; invalid → **600116** |
| – | `gzip` | boolean | `dat` is Base64(GZIP(data)) | — |

Notes:
* `rtservlet` is only examined when `dat` is absent **and** `fileid` is present.
* When `fileid` is present, every operation stops validating after the id/version checks; the downloaded envelope
  is parsed again from scratch with `servicesRequired=true` (§4).

### 3.2 Launch‑URL‑only parameters

| Param | Used in | Meaning |
|---|---|---|
| `v` | `websocket`, `service` | protocol version of the channel (§11). Absent/invalid → `0` → unsupported → app shows error and exits. |
| `jvc` | all | JavaScript version code (int). AutoScript 1.10.x sends `4`. `jvc > 3` with major version 4 ⇒ version upgraded to **4.1** and WebSocket requests processed **asynchronously** (`#wait`). |
| `ports` | `websocket` (optional), `service` (required) | comma‑separated candidate ports (§2.7). WebSocket default if absent: **`63117`**. Service without ports → **620013** `PORTS_NOT_FOUND`. |
| `idsession` | `websocket`, `service`; also inside every message | session token (§2.7). |
| `dlgload` | argv[0] of any mode | `false` disables progress dialogs. |

### 3.3 `afirma://websocket` and `afirma://service`

```
afirma://websocket?ports=<p1>[,<p2>…]&v=<ver>&jvc=<int>&idsession=<id>[&dlgload=false]
afirma://service?ports=<p1>[,<p2>…]&v=<ver>&jvc=<int>&idsession=<id>[&dlgload=false]
```
Both are recognised only with the exact prefixes `afirma://websocket?`, `afirma://websocket/?`,
`afirma://service?`, `afirma://service/?`. Behaviour in §5.1 / §5.2. On success `launch()` returns `OK`
(not sent anywhere). Fatal errors:

| Condition | WebSocket | Service |
|---|---|---|
| unsupported `v` (WS: major ∉ {3,4}; service: major ∉ {1,2,3}) | dialog (code 620011) + `halt(0)` | dialog + error string returned → process exits (`forceCloseApplication(0)` in `main`) |
| `autofirma.pfx` missing/unloadable | dialog **220008** + `halt(0)` | dialog 220008, exit |
| no port could be bound | dialog **220001** + `halt(0)` | dialog 220001 + `halt(0)` |
| `ports` absent | default 63117 | **620013** dialog, exit |

### 3.4 `afirma://sign`, `afirma://cosign`, `afirma://countersign`

```
afirma://sign?op=sign&format=<fmt>&algorithm=<alg>[&dat=<data>][&properties=<b64props>][&ksb64=<b64>]
             [&sticky=true|false][&resetsticky=true|false][&id=<id>][&stservlet=<url>][&key=<des8>]
             [&cipher=<b64json>][&aw=true][&ver=<v>][&mcv=<ver>][&appname=<name>][&servicetimeout=<ms>]
             [&gzip=true][&idsession=<id>][&jvc=<n>][&<plugin-specific>=…]
```

Parameters (after §3.1):

| Param | Req. | Meaning / encoding | Validation → error |
|---|---|---|---|
| `id` (else `fileid`) | direct mode | operation id = Storage file name for the result | §2.7 → **600120** |
| `ver` | no | requested protocol version (direct mode only), default `"0"` | — |
| `appname` | no | URL‑decoded **again** (UTF‑8); informational only (never used by the app) | — |
| `op` | **yes in practice** | `sign` / `cosign` / `countersign` (case‑insensitive) — **this**, not the URL host, selects the crypto operation (⚠ QUIRK). Missing/other → null → NPE later → **200115** `UNKNOWN_SIGNING_ERROR`. | — |
| *(fileid present → stop here)* | | | |
| `stservlet` | direct mode | Storage endpoint (§2.6) | local → **600412**; invalid → **600411** (⚠ batch codes reused); absent while `id` present → **600402**. Absent and no `id` → no error now, but the final upload NPEs → **200115**. |
| `format` | **yes** | signature format name (case‑insensitive): `CAdES`, `CAdEStri`, `CAdES-ASiC-S`, `CAdES-ASiC-S-tri`, `CMS/PKCS#7`, `XAdES`, `XAdEStri`, `XAdES-ASiC-S`, `XAdES-ASiC-S-tri`, `XAdES Detached`, `XAdES Enveloped`, `XAdES Enveloping`, `XMLDSig`, `XMLDSig Detached`, `XMLDSig Enveloped`, `XMLDSig Enveloping`, `FacturaE`, `Factura-e`, `FacturaEtri`, `PAdES`, `PAdEStri`, `Adobe PDF`, `Adobe PDF TriPhase`, `ODF`, `ODF (Open Document Format)`, `OOXML`, `OOXML (Office Open XML)`, `NONE`, `NONEtri`, or `AUTO` (any case) | missing → **600104**; unknown name → **600105** (at processing time) |
| `algorithm` | **yes** | one of `SHA1`, `SHA256`, `SHA384`, `SHA512`, `SHA1withRSA`, `SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`, `SHA1withECDSA`, `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA` (exact, case‑sensitive). Only the digest part matters: the final algorithm is `<digest>with<RSA\|DSA\|ECDSA>` according to the **key type** of the selected certificate. | missing → **600106**; not in list → **600107** |
| `properties` | no | extra params (§2.4) | never fails |
| `sticky` | no | keep the selected key for later operations in the same process (§12.2) | — |
| `resetsticky` | no | ignore the cached key this time | — |
| `keystore` / `ksb64` | no | §2.5 | — |
| other unknown keys | no | collected into a map passed to signature plugins ("anotherParams") | — |

Known‑parameter list (anything else goes to plugins): `format, algorithm, id, ver, sticky, resetsticky,
properties, dat, gzip, rtservlet, stservlet, key, fileid, keystore, ksb64, aw, mcv, appname`
(note: `op`, `cipher`, `idsession`, `jvc`, `servicetimeout`, `v` **are** forwarded to plugins).

Processing (after parameters are valid), in order:
1. Protocol compatibility (§11) → **620011**; `mcv` > app version → **500005**.
2. Remove extra param `profile`.
3. Select a data processor: an installed plugin with "inline process" permission whose processor triggers on the
   operation, else the native processor (the rest of this list).
4. If a cipher config exists, instantiate it (§8) — failure (e.g. JSON invalid, AES without `legacydes`) →
   **200117** `POSTPROCESING_SIGNATURE`.
5. Resolve the signer for `format` (not for `AUTO`) → unknown → **600105**. Triphase signers receive an HTTP
   client whose read timeout = `servicetimeout` if given.
6. If no data: if the signer can work without data (XAdES/XAdEStri with `format=XAdES Externally Detached` or
   `useManifest=true` in extra params) continue; otherwise show a **file‑open dialog** (title "select file to
   sign" for `sign`, "select signature" for cosign/countersign; extensions/description/dir/name from
   `filenameExts`, `filenameDescription`, `filenameCurrentDir`, `filenameActualName`). The chosen file name is
   remembered and returned as `extraData {"filename": …}` (§7.1). Read failure → **200003**.
7. `AUTO`: `sign` → PDF⇒`PAdES`, FacturaE⇒`FacturaE`, XML⇒`XAdES`, else `CAdES`; cosign/countersign → detect the
   signer from the existing signature; failure → **501009**.
8. Legacy explicit XAdES (§2.4 `mode`).
9. `checkSignatures=true` → validate existing signatures (may prompt; headless → fail).
   Invalid → its error code or **500002** (for `sign`, "no signature present" is not an error).
10. `ExtraParamsProcessor.expandProperties(extraParams, data, format)` → policy incompatibility → **501008**.
11. Visible PDF signature dialog (§2.4) → **501010**.
12. Keystore resolution and certificate selection (§12.3), sticky handling (§12.2). No valid certificate →
    **501001**; keystore errors → their code or **201101**; cancel → cancellation (§7.3).
13. Compose signature algorithm from key type → failure **200110** `INVALID_SIGNING_KEY`.
14. Sign (local or three‑phase §10). Wrong PIN → the certificate dialog is shown again, pre‑filtered to the same
    certificate (keystore reloaded). Locked keystore → its error, sticky cleared. User‑confirmation requests
    (`RuntimeConfigNeededException`, e.g. LTS signature, certified PDF) → Yes/No dialog → retry with the
    corresponding extra param set to `true`; password requests → prompt; denied/headless → error.
    `IllegalArgumentException` → **600121**; unknown → **200115**.
15. Build the result (§7.1).

### 3.5 `afirma://signandsave`

```
afirma://signandsave?op=signandsave&cop=<sign|cosign|countersign>&format=<fmt>&algorithm=<alg>
                    [&filename=<name>][&dat=…][&properties=…][&ksb64=…][&sticky=…][&resetsticky=…]
                    [&id=…][&stservlet=…][&key=…][&cipher=…][&aw=…][&ver=…][&mcv=…][&servicetimeout=…]
```
Same as §3.4 with these differences:
* The crypto operation comes from **`cop`** (not `op`).
* `algorithm` list **excludes** the `…withECDSA` names (they fail with **600107**).
* `filename`: default output file name; must not contain any of `\ / : * ? " < > |` → error **600306**
  (`FILENAME_TO_SAVE_NOT_FOUND`, sic).
* `appname` is not interpreted (goes nowhere); unknown parameters are **not** forwarded to plugins.
* `servicetimeout` is parsed but **not applied** to triphase signers in this operation (⚠ QUIRK).
* After signing, a **save dialog** is shown for the signature: title key `ProtocolLauncher.31`, directory
  `filenameSaveCurrentDir`, extensions `filenameSaveExts` (comma list), description `filenameSaveDescription`;
  proposed name = `filename` if given, else (input file name without extension, or the localized default
  "firma") passed through the signer's "signed name" rule (e.g. `x.pdf` → `x_signed.pdf`, CAdES `.csig`, XAdES
  `.xsig`). Save failure → **200301**. Cancel → cancellation.
* Signature‑validation failures always report **500002** (not the validator's own code).
* Result: identical to sign (§7.1) — the signature is also returned to the page.

### 3.6 `afirma://selectcert`

```
afirma://selectcert?op=selectcert[&properties=…][&ksb64=…|&keystore=…][&sticky=…][&resetsticky=…]
                   [&id=…][&stservlet=…][&key=…][&cipher=…][&aw=…][&ver=…][&mcv=…]
```
* `id`/`fileid` → §2.7 → **600201**. `ver` default `0`. `stservlet` rules as §3.4 (same 6004xx codes).
* `properties` → filters (`filter`, `filters`, `filters.N`, `headless`, `mandatoryCertSelection`).
* `sticky=true` and not `resetsticky` and a cached key exists → returns the cached certificate **without UI**.
  Otherwise shows the certificate dialog; on success caches the key if `sticky=true`, else clears the cache.
* No certificates → **502001**. Keystore error → its code or **201101**.
* Result: the signing certificate (DER), §7.1. In direct mode the result is uploaded **twice** (once inside the
  operation, once by the launcher; identical content) — harmless but observable (⚠ QUIRK).

### 3.7 `afirma://batch`

```
afirma://batch?op=batch&dat=<b64url(batch JSON or XML)>[&jsonbatch=true][&localBatchProcess=true]
              [&batchpresignerurl=<url>&batchpostsignerurl=<url>][&needcert=true][&properties=…]
              [&ksb64=…][&sticky=…][&resetsticky=…][&id=…][&stservlet=…][&key=…][&cipher=…][&aw=…]
              [&ver=…][&mcv=…][&appname=…][&servicetimeout=…]
```

| Param | Req. | Meaning | Validation → error |
|---|---|---|---|
| `id` (else `fileid`) | direct | result id | §2.7 → **600410** |
| `ver`, `appname` | no | as §3.4 | — |
| *(fileid → stop)* | | | |
| `localBatchProcess` | no | (exact case) `true` → sign locally, no servers (§9.4) | — |
| `batchpostsignerurl` | unless local | JSON/XML batch postsign service | missing → **600406**; local → **600416**; invalid → **600415** (checked before presigner) |
| `batchpresignerurl` | unless local | presign service | missing → **600405**; local → **600414**; invalid → **600413** |
| `stservlet` | direct | §3.4 | 600412 / 600411 / 600402 |
| `properties` | no | extra params (cert filters, `headless`, …) | — |
| `sticky`, `resetsticky` | no | §12.2 | — |
| `needcert` | no | append the signing certificate to the result | — |
| `jsonbatch` | no | `dat` is a JSON batch (else XML batch) | — |
| `dat` | yes | the batch definition (Base64url) | if absent the batch signer fails → **600420** (local batch: **200412**) |

Batch processing and result: §9.

### 3.8 `afirma://save`

```
afirma://save?op=save&dat=<data>[&title=<t>][&filename=<name>][&exts=<ext>][&desc=<d>]
             [&id=…][&stservlet=…][&key=…][&aw=…][&ver=…][&mcv=…]
```

| Param | Req. | Meaning | Validation → error |
|---|---|---|---|
| `dat` or `fileid` | **yes** | data to save | neither → **600300** (checked after common params) |
| `id`/`fileid` | direct | | §2.7 → **600303** |
| `ver` | no | default 0 | — |
| `stservlet` | direct | (checked even when `fileid` is present) | 600412 / 600411 / 600402 |
| `title` | no | dialog title; default localized "Guardar fichero" (es) / "Save file" (en) | — |
| `filename` | no | proposed name | contains `\ / : * ? " < > \|` → **600306** |
| `exts` | no | **one** extension, used as a single filter entry (e.g. `pdf`) | contains any of `\ / : * ? " < > \| ;` or space → **600307** |
| `desc` | no | filter description; if `exts` given and `desc` doesn't end with `)`, the app appends ` (*.<ext1>*.<ext2>…)` built from `exts.split(",")` (note: no separator between items, ⚠ QUIRK) | — |

* AutoScript in **server mode** sends the keys `extension` and `description` instead of `exts`/`desc`
  (JS bug) — the Java app ignores them (no filter, no description). WebSocket/service modes send `exts`/`desc`.
* Result: `OK` (§7.1). Dialog cancel → cancellation. Write failure → **200301**.

### 3.9 `afirma://load`

```
afirma://load?op=load[&title=<t>][&exts=<e1,e2>][&desc=<d>][&filePath=<dir>][&multiload=true|false][&ver=…][&mcv=…]
```
* Common params (§3.1) are parsed too (e.g. `key`, `fileid`), but **no** id validation and **no** Storage URL is
  recorded: in direct mode the final upload fails (NPE) → **200600** (⚠ load only works over sockets; AutoScript
  refuses it in server mode with AS500008/AS500009).
* `title` (default system title), `exts` (comma list), `desc`, `filePath` (initial directory/file; empty → none),
  `multiload` (multi‑selection).
* Result: `name:Base64std(content)` items joined with `|` (§7.1). Read failure → **200601**. Not encrypted even if
  `key` is present.

### 3.10 AutoScript public API → protocol operation map

Every function exported by `AutoScript` (alias `MiniApplet`) in `autoscript.js` 1.10.1:

| JS API | Protocol operation / effect | Parameters produced (besides common ones) | Success callback |
|---|---|---|---|
| `cargarAppAfirma(clientAddress, keystore)` / `cargarMiniApplet` | selects the transport (§1); no traffic. `keystore` default: `MOZ_UNI` on Firefox, else none | — | — |
| `sign(dataB64, algorithm, format, params, ok, err)` | `afirma://sign` | `op=sign`, `algorithm`, `format`, `properties=B64(params)`, `dat=B64U(data)` (or URL), `ksb64`, `sticky`/`resetsticky`, `appname`, `servicetimeout` | `(signatureB64, certB64, extraText)` |
| `coSign(signB64, dataB64, …)` | `afirma://cosign` (**`dataB64` ignored**) | `op=cosign`, `dat=B64U(sign)` … | as sign |
| `cosign(signB64, algorithm, format, params, ok, err)` | `afirma://cosign` | as sign | as sign |
| `counterSign(signB64, algorithm, format, params, ok, err)` | `afirma://countersign` | as sign | as sign |
| `signAndSaveToFile(opId, dataB64, algorithm, format, params, outputFileName, ok, err)` | `afirma://signandsave` | `op=signandsave`, `cop=<opId>`, `filename=<outputFileName>` + sign params | as sign |
| `selectCertificate(params, ok, err)` | `afirma://selectcert` | `op=selectcert`, `properties`, `ksb64`, `sticky`/`resetsticky` | `(certB64)` |
| `createBatch(algorithm, format, suboperation, extraparams)` / `addDocumentToBatch(id, datareference, format, suboperation, extraparams)` / `setLocalBatchProcess(bool)` | local JSON builder (§9.2) | — | — |
| `signBatchProcess(stopOnError, preUrl, postUrl, certFilters, ok, err)` | `afirma://batch` (JSON) | `batchpresignerurl`, `batchpostsignerurl`, `properties=B64(certFilters)`, `needcert=true`, `jsonbatch=true`, `[localBatchProcess=true]`, `dat=B64U(JSON)` | `(resultObject, certB64)` |
| `signBatch(batchB64, preUrl, postUrl, params, ok, err)` | `afirma://batch` (XML) | `batchpresignerurl`, `batchpostsignerurl`, `properties`, `needcert=true`, `dat` | `(resultB64, certB64)` |
| `saveDataToFile(dataB64, title, fileName, extension, description, ok, err)` | `afirma://save` | `title`, `filename`, `exts` (server mode: `extension`), `desc` (server mode: `description`), `dat` | `("OK"\|"SAVE_OK")` or `()` in server mode |
| `getFileNameContentBase64(title, extensions, description, filePath, ok, err)` | `afirma://load`, `multiload=false` (not in server mode: AS500008) | `title`, `exts`, `desc`, `filePath` | `(fileName, dataB64)` |
| `getMultiFileNameContentBase64(…)` | `afirma://load`, `multiload=true` (not in server mode: AS500009) | idem | `([names], [datasB64])` |
| `setStickySignatory(bool)` | state → `sticky=true` / next call `resetsticky=true` (server mode desktop: JS emulation §12.2) | | |
| `setKeyStore(ksType)` | state → `ksb64`(+`keystore` in service mode); also forces `resetsticky=true` next | | |
| `setMinimumClientVersion(v)` | state → `mcv=<v>` first query param | | |
| `setAppName(name)` | state → `appname` (WS/service: inverted‑logic bug, sends hostname only when set) | | |
| `setServiceTimeout(ms)` | state → `servicetimeout` (service mode: JS ReferenceError) | | |
| `enableProgressDialog(bool)` | `dlgload=false` on the launch URL (server mode: never sent) | | |
| `setServlets(storage, retriever)` | server‑mode endpoints + `op=check` probes | | |
| `setForceWSMode(bool)` | forces **server** mode | | |
| `setPortRange(min, max)` | port range for `ports=` | | |
| `setLocale(locale)` | **JS only** (dialog texts) | | |
| `getCurrentLog(ok, err)` | **JS only**: error `AS500010` | | |
| `echo()` | **JS only**: returns `"Cliente JavaScript"` | | |
| `checkTime(type, maxMillis, url)` | **JS only** (HTTP `Date` header) | | |
| `downloadRemoteData(url, ok, err)` | **JS only** (XHR → Base64) | | |
| `getBase64FromText`, `getTextFromBase64` | **JS only** | | |
| `getErrorMessage/getErrorType/getErrorCode/getErrorCodeNumber` | **JS only** (last error) | | |
| `isAndroid`, `isIOS`, `isJNLP` (false), `needNativeAppInstalled` (true), `setForceAFirma`, `setJnlpService` (no‑ops) | **JS only** | | |

### 3.11 Parameter encoding differences between AutoScript transports

| Aspect | WebSocket (A) | Service (B) | Server mode (C) |
|---|---|---|---|
| URL shape | `afirma://<op>?[mcv=…&]op=<op>&idsession=<id>&…` | `afirma://<op>?[mcv=…&]op=<op>&…` (no `idsession` in URL) | `afirma://<op>?jvc=4[&mcv=…]&<op params>&ver=4&op=<op>&id=<id>&appname=…&key=…[&cipher=…][&stservlet=…][&aw=true]` |
| Percent‑encoding | `encodeURIComponent` except `properties`, `ksb64`, `dat`, `servicetimeout` (raw URL‑safe Base64 with `=`) | all values `encodeURIComponent` | all values `encodeURIComponent` |
| `properties` / `ksb64` alphabet | URL‑safe | standard | standard |
| `dat` | URL‑safe Base64 (also mangles URLs) | URL‑safe unless `http(s)` URL | URL‑safe, `\r\n` stripped, unless URL |
| `keystore` (plain) | no | yes (both `keystore` and `ksb64`) | no |
| Protocol version | `v=4` on launch URL | `v=4` on launch URL (rejected, §5.2) | `ver=4` in each request |
| Cipher | none | none | `key` always, `cipher` (AES) in secure contexts |

---

## 4. Envelopes for indirect requests (`fileid`)

When the page's URL would exceed 2000 characters, AutoScript (server mode only) uploads the parameter list to
Storage and launches:

```
afirma://<op>?jvc=4[&mcv=<v>]&fileid=<FID>&rid=<RID>&rtservlet=<retriever URL>&stservlet=<storage URL>
             &key=<des8>[&cipher=<b64 JSON>]
```

App procedure (`ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet` + re‑parse):

1. Parse the URL as usual; the op's id falls back to `fileid` (since `id` is absent); `rtservlet` validated;
   parsing stops at the `fileid` check (so `stservlet` is **not** yet known → errors in steps 2–4 are only shown
   in a dialog, never uploaded, and the page eventually times out). Exception: `save` validates `stservlet`
   even with `fileid`; for `save` the failure of steps 2–4 is uploaded to Storage under id = `fileid` as the
   **raw Java exception message** (not formatted per §7.2, ⚠ QUIRK), e.g.
   `Se recupera un error desde el servidor intermedio: ERR-06:=…`.
2. Wait for TLS context initialisation, then **POST** to `<rtservlet>` with body `op=get&v=1_0&id=<FID>`
   (§6.3). On `SocketTimeoutException` → op‑specific **4011xx** "timeout" code (401106 sign, 401107 selectcert,
   401108 batch, 401109 save, 401110 load, 401111 signandsave); other I/O → **4011xx** (401100 sign, 401101
   selectcert, 401102 batch, 401103 save, 401104 load, 401105 signandsave).
3. If the response has more than 8 bytes and its first 8 bytes, lower‑cased, start with `err-` → error
   **220003** `ERROR_RECIVED_FROM_CLIENT`.
4. Decrypt the response with the cipher config built from the URL's `key`/`cipher` (§8). Cipher‑config JSON
   invalid → reported like an I/O error (4011xx above); decryption failure → **220002**
   `DECRYPTING_PARAMS_ERROR`. ⚠ QUIRK: if there is **no** cipher config the data is `null` and the subsequent
   XML parse fails (generic error, see 4.1) — i.e. `key` is mandatory with `fileid`.
5. Parse the plaintext as the **XML envelope** (below) and run the operation's parameter parsing again with
   `servicesRequired = true` over the resulting map (the XML parameters completely replace the URL ones; e.g.
   `id`, `stservlet`, `key`, `cipher` are taken from the XML).

### 4.1 XML envelope (what AutoScript uploads)

```xml
<sign><e k="format" v="CAdES"/><e k="algorithm" v="SHA256withRSA"/><e k="properties" v="…"/><e k="dat" v="…"/><e k="ver" v="4"/><e k="op" v="sign"/><e k="id" v="RID…"/><e k="appname" v="www.example.org"/><e k="key" v="04719233"/><e k="cipher" v="eyJ…"/><e k="stservlet" v="https://…/StorageService"/><e k="aw" v="true"/></sign>
```

* Root element name = operation name (`sign`, `cosign`, `countersign`, `signandsave`, `selectcert`, `batch`,
  `save`). Parser rule: map["op"] = root name, except when the root is named `op` (case‑insensitive) → `"SIGN"`.
  Child `<e k="op">` entries (always present from AutoScript) then **overwrite** it.
* Every child node of the root must be an element named exactly `e` with attributes `k` and `v`. Whitespace
  text nodes and comments count as children (the DOM builder does not ignore them), so any whitespace/newline
  between elements makes the parser fail (⚠ the envelope must be compact). A `DOCTYPE` is rejected
  (`disallow-doctype-decl`); namespace‑aware, non‑validating, secure processing. Failure → `AOException`
  **300202** `INVALID_OPERATION_XML`, which the launcher does **not** report as such: it falls into the
  operation's generic handler → **200115** (sign, cosign, countersign, signandsave), **200201** (selectcert),
  **200413** (batch), **200305** (save), **200600** (load), shown in a dialog and returned.
* Each value is passed through `URLDecoder.decode(v, UTF‑8)` (so `+`→space, `%HH` decoded).
  ⚠ QUIRK (JS↔Java mismatch): AutoScript writes values **raw** (not percent‑encoded, not XML‑escaped). Standard
  Base64 values (`properties`, `cipher`) that contain `+` are corrupted (`+`→space→skipped by the Base64
  decoder). `&`/`<`/`"` in values (e.g. in URLs) break the XML. A byte‑compatible app reproduces this; a
  tolerant app MAY decode `v` without turning `+` into space, but must document the deviation.
* No XML declaration. The plaintext that is encrypted (§8) and uploaded is the UTF‑8 XML text itself (AutoScript
  builds it, Base64‑encodes it internally and decodes it again before encrypting).
* Keys in the envelope: everything the direct URL would carry, plus `ver`, `op`, `id`, `appname`, `key`,
  `cipher`, `stservlet`, `aw`; when `enableProgressDialog(false)` was used, AutoScript also writes
  `<e k="dlgload" v="undefined"/>` (ignored). `jvc` is not in the envelope (it is in the URL).
* `rid` in the URL is the id the page polls for; it equals the envelope's `id`. The app never reads `rid`.

### 4.2 JSON envelope (batch, unreachable)

`TriphaseDataParser.parseParamsListJson`: `{"params":[{"k":"<key>","v":"<url-encoded value>"}, …]}` — entries
without `k` or `v` ignored; values URL‑decoded. It is used only when `fileid` is present **and** `jsonbatch=true`
is known *before* download, which never happens (the batch parser stops at `fileid` before reading `jsonbatch`),
so in practice batch envelopes are always parsed as XML (§4.1). A Rust app MAY support both by sniffing the first
non‑blank byte (`{` vs `<`).

---

## 5. Transports

### 5.0 TLS material shared by (A) and (B)

* Key store file **`autofirma.pfx`**, type **PKCS#12**, store password **`654321`**, key password **`654321`**
  (`SecureSocketUtils`). Looked up, in order:
  1. the application directory = directory containing the running JAR/executable (JNLP deployments: the
     "alternative" directory below, or `java.io.tmpdir`);
  2. the "alternative" directory: Windows `%ALLUSERSPROFILE%\Autofirma`, Linux `~/.afirma/Autofirma`,
     macOS `$HOME/Library/Application Support/Autofirma`.
  Not found / unreadable → error **220008** `LOADING_SSL_KEYSTORE_ERROR` (dialog, then exit).
* The PKCS#12 is created by the installer/configurator (separate spec): leaf certificate CN `127.0.0.1`,
  SAN = iPAddress `127.0.0.1`, dNSName `127.0.0.1`, dNSName `localhost`, issued by a locally generated root that
  the installer adds to the OS/browser trust stores. The app just uses the first key entry.
* SSL context protocol name `"TLSv1"` (Java `SSLContext.getInstance("TLSv1")`), default key manager, **no client
  authentication**. ⚠ AMBIGUOUS: on modern JDKs a server context obtained this way still enables every protocol
  version the JDK supports (TLS 1.2/1.3); the Rust app should offer TLS 1.2 and 1.3.
* (B) restricts cipher suites to this exact list (TLS 1.3 suites excluded ⇒ TLS ≤ 1.2):
  `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
  TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_RSA_WITH_AES_256_CBC_SHA256,
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  TLS_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA`. (A) uses the library defaults.

### 5.1 (A) WebSocket server (`AfirmaWebSocketServerManager`, `AfirmaWebSocketServer`, `AfirmaWebSocketServerV4Sup`)

Library: Java‑WebSocket 1.6.0 (RFC 6455, TLS via `DefaultSSLWebSocketServerFactory`).

#### 5.1.1 Start‑up

1. Version check: major of `v` must be **3** or **4** (`checkSupportProtocol`); else `UnsupportedProtocolException`
   (code 620011) → error dialog, `halt(0)`.
2. Load TLS context (§5.0) → failure: dialog 220008, `halt(0)`.
3. Set system property `websockets.optimizedForVdi` = preference "VDI optimisation" (⚠ AMBIGUOUS: nothing in this
   repository reads it; probably intended for the WebSocket library — can be ignored).
4. Port selection: iterate `ports` **in the given order** (default `[63117]`); for each create the server bound to
   **`0.0.0.0:<port>`** (all interfaces! `new InetSocketAddress(port)`, `SO_REUSEADDR=true`) and start it. If the
   constructor/start throws, try the next port. Because binding happens asynchronously inside the library, a
   `BindException` reported later through `onError` triggers a **restart on the next remaining port** (same
   `ChannelInfo` cursor). If no port remains (or the retry fails) → dialog 220001 + `halt(0)` (or `halt(-1)` on
   a failed rebind retry).
5. Server class: major 4 → **V4Sup** (`v=4`, or 4.1 after upgrade), major 3 → **legacy v3**.
6. Asynchronous mode for V4Sup = `jvc > 3`.
7. A shutdown hook stops the server on process exit.
8. **Initial inactivity timer: 30 000 ms.** If after 30 s **no WebSocket connection has been opened**, the app
   exits (`halt(0)`). The timer is cancelled by the first *accepted* message (`markAsWorking`); if a connection
   was opened but no valid message ever arrives, the app does **not** exit by this timer (⚠ QUIRK).

The `launch()` call returns `OK` and the process stays alive serving the socket; `main` does not exit for
`afirma://websocket` URLs.

#### 5.1.2 Connection handling and lifetime

* No path, sub‑protocol or Origin checks; the page connects to `wss://127.0.0.1:<port>` (path `/`).
* The **first** connection that opens is remembered as "the client". When *that* connection closes (any code,
  local or remote) the app exits immediately (`halt(0)`). Closing other connections has no effect.
  (⚠ AutoScript may open several sockets while probing; if the browser closes the first one, the app exits.)
* Library keep‑alive: `setConnectionLostTimeout(60)` seconds before each synchronous operation, **240** s if the
  message starts with `afirma://batch?` or `afirma://batch/?` (Ping/Pong based; a lost connection closes the
  socket → app exits).
* All frames are **text** frames; one request per frame, one response per frame (no fragmentation at protocol
  level, no size limit enforced by the app).

#### 5.1.3 Messages accepted by the V4 server (current protocol)

For **every** incoming text message, in order:

1. **Origin host check**: the peer address must be exactly IPv4 `127.0.0.1`. Otherwise reply with the error
   string for **420001** `EXTERNAL_REQUEST` (format per negotiated version, §7.2) and ignore the message.
   (`::1` is rejected.)
2. **Session check** (only if a valid `idsession` was given at launch): extract the session id from the message:
   find the first occurrence of `idsession=`; the id runs up to the next `&`, or to the end of the message with a
   trailing `@EOF` removed. If it differs from the launch id (or is absent) → reply with the error string for
   **620010** `INVALID_SESSION_ID` and ignore.
3. Cancel the initial inactivity timer.
4. If the message starts with `echo=` → reply **`OK`**. AutoScript sends `echo=-idsession=<id>@EOF`.
5. Otherwise:
   * **Asynchronous mode** (`jvc > 3`, the AutoScript 1.10 behaviour) — `WebSocketServerOperationHandler`:
     * message starting with `getresult?` → look up the operation registered for this session id:
       none → reply `#wait`; still running → reply `#wait`; finished → reply with the **operation result string**
       and forget the operation.
     * any other message → start a worker thread running `launch(message, version, bySocket=true)`, register it
       under the session id (replacing any previous one), reply **`#wait`** immediately.
   * **Synchronous mode** (`jvc ≤ 3`): run `launch(message, version, true)` on the socket thread (set keep‑alive
     60/240 s first) and reply with its return value.

Exchange as performed by AutoScript 1.10.1 (async):
```
page → app : echo=-idsession=Q3k9aZ0bT1cL2mN4pX7r@EOF
app  → page: OK
page → app : afirma://sign?op=sign&idsession=Q3k9aZ0bT1cL2mN4pX7r&algorithm=SHA512withRSA&format=CAdES&properties=bW9kZT1pbXBsaWNpdA==&ksb64=TU9aX1VOSQ==&sticky=false&dat=SG9sYQ==
app  → page: #wait
             (page waits 2000 ms after each #wait)
page → app : getresult?idsession=Q3k9aZ0bT1cL2mN4pX7r
app  → page: #wait                                (…repeated while the user works…)
page → app : getresult?idsession=Q3k9aZ0bT1cL2mN4pX7r
app  → page: MIIF…(cert b64url)|MIAG…(signature b64url)[|eyJmaWxlbmFtZSI6…(extra b64url)]
```
The page repeats echo → request for every new operation on the same socket. The page never closes the socket
explicitly; it closes when the page is unloaded → app exits.

Edge cases (⚠): if the worker thread died with an uncaught exception its result is `null`; Java‑WebSocket then
throws when sending and the page waits forever. Session ids absent in the launch URL → all session checks pass and
all operations share the `null` session slot.

#### 5.1.4 Legacy v3 server (`v=3`)

* No host check, no session check, always synchronous: `echo=…` → `OK`; anything else →
  `launch(message, version = 0, true)` and reply with the result.
* ⚠ QUIRK: the version passed is **0**, which `isCompatibleWith` rejects for every data operation (supported
  majors are 1–4), so every operation answers `SAF_21: <localized text>` (620011 in legacy format). The v3
  WebSocket path is effectively **dead**; a Rust implementation MAY treat it as version 3 instead (document the
  deviation).

### 5.2 (B) Legacy local HTTPS "service" socket (`ServiceInvocationManager`, `CommandProcessorThread`)

#### 5.2.1 Start‑up

* Version: major of `v` must be **1, 2 or 3**; else `UnsupportedProtocolException` (620011) → error dialog, the
  error string is returned and the process exits. ⚠ **AutoScript 1.10.1 sends `v=4` → the service mode never
  works with AutoFirma 1.10** (page times out with AS620020). A Rust implementation should decide whether to also
  accept major 4 here (recommended, harmless) — flagged in §13.
* `ports` mandatory (620013). Ports are tried **in order** with a blocking TLS server socket (default bind address
  = all interfaces); `BindException`/other errors → next port; none → dialog 220001, `halt(0)`.
* `SO_REUSEADDR`, cipher suites per §5.0.
* An inactivity timer of **90 000 ms** (Swing `Timer`, repeating) is started; when it fires the app exits
  (`halt(0)`); on macOS it first runs `kill -9 $(ps -ef | grep <idsession> | awk '{print $2}')` (this is why
  `idsession` must be alphanumeric). Each accepted *command* stops the timer while processing; sending a response
  restarts it (only if it had been stopped — invalid requests do not keep the app alive).
* Accept loop forever; **one thread per TCP connection**; each connection carries exactly one request and is
  closed after the response.

#### 5.2.2 Request framing (raw, not a real HTTP parser)

* Peer must be `127.0.0.1`, `0:0:0:0:0:0:0:1` or the literal host string `localhost`; otherwise the socket is
  closed silently.
* The app reads raw bytes (UTF‑8 decoded in 2048‑byte chunks) **until the text `@EOF` is seen**. Whitespace‑only
  reads are retried up to 10 times, then the request is ignored. The bytes read include the HTTP request line and
  headers; they are not parsed as HTTP.
* The text `idsession` must appear before `@EOF`; the session id is the substring from
  `index("idsession") + 10` (i.e. after `idsession=`) up to `@EOF`. If the app has a session id and it differs →
  respond with the error for **620010** and close. The "request data" is everything before `idsession` (or before
  `@EOF` if absent).
* Command detection: the **whole request text** (headers included) is searched with `indexOf` for these markers,
  in this priority: `cmd=`, `echo=`, `fragment=`, `firm=`, `send=` (first marker found in that priority order).
  The command argument is the text after the marker up to the `idsession` position.
* All responses: `HTTP/1.1 200 OK\n` + headers `Connection: close\n`, `Pragma: no-cache\n`,
  `Server: Cliente @firma\n`, `Content-Type: text/html; charset=utf-8\n`, `Access-Control-Allow-Origin: *\n`,
  then `\n`, then **URL‑safe Base64 (padded) of the UTF‑8 response text**. Note: **LF line endings, no
  `Content-Length`**; the body ends when the socket is closed. (An unused 500 variant exists without the `\n`
  after the status line.)

#### 5.2.3 Commands

State is **process‑global** (shared by all connections): `request[]` (received fragments), `toSend[]` (response
parts), `parts`.

| Body sent by the page | App action | Response text (before Base64url) |
|---|---|---|
| `echo=<x>idsession=<id>@EOF` | stop timer; if `<x>` contains `-` → reset global state | `OK` |
| `cmd=<b64url(url)>idsession=<id>@EOF` | decode (URL‑safe Base64); must start with `afirma://` and must not be `afirma://service…`. **save**: run; result `OK` → `SAVE_OK`, `CANCEL` → `CANCEL`, anything else → error (see below). **others**: if `toSend` empty, run `launch(url, version, true)` and split the result into parts of **1 000 000 characters**; reply with the number of parts | `SAVE_OK` / `CANCEL` / `<n>` |
| `fragment=@<i>@<n>@<b64url(chunk)>idsession=<id>@EOF` | store decoded chunk at index `i‑1` (replace if already `i` items) | `MORE_DATA_NEED` if `i<n`, `OK` if `i==n` |
| `firm=idsession=<id>@EOF` | concatenate stored fragments into the URL and process like `cmd` (save: `SAVE_OK`/`CANCEL`) | `<n>` (number of parts) |
| `send=@<p>@<n>idsession=<id>@EOF` | `1 ≤ p ≤ n` else error | part `p` of the result |

Errors while processing a connection → the response text is the formatted error (§7.2) for:
* invalid session id → **620010**;
* exception while reading the socket → **420502**;
* no command marker found in the request → **620016** (`MALFORMED_REQUEST_TO_SOCKET`);
* *any* failure inside a command (Base64 error, `cmd` not an `afirma://` URL, save result neither `OK` nor
  `CANCEL`, bad fragment numbers, `send` part out of range, I/O while answering) → **401200**
  (`SENDING_RESULT_OPERATION`; the Java code wraps them all into an `IOException`);
* `OutOfMemoryError` → the literal text **`MEMORY_ERROR`** (Base64url‑encoded like any response);
* other runtime errors → **200118**.

With the only supported versions (≤ 3) these are always legacy `SAF_nn: …` strings (§7.2). Note that the result
of a normal operation is returned as the parts payload even if it is an error string (e.g. `CANCEL` or
`SAF_09: …` becomes 1 part).

The page's side (AutoScript `AppAfirmaJSSocket`) POSTs these bodies to `https://127.0.0.1:<port>/afirma` with
`Content-type: application/x-www-form-urlencoded`; fragments are used when the URL exceeds 12 000 chars (IE) /
458 752 (Firefox) / 1 048 576 (others); it then fetches parts `1..n` with `send=`.

### 5.3 (C) Direct launch with intermediate server

Flow for a data operation launched directly (`bySocket=false`):

1. Parse parameters (§3); if `fileid`, download/decrypt/parse the envelope (§4).
2. Protocol version = `ver` (default 0) possibly upgraded to 4.1 (`jvc>3`).
3. If `aw=true`: start the **active‑waiting thread** (§6.4) that PUTs `#WAIT` every 10 s.
4. Run the operation (UI).
5. Build the result string (§7.1) or error string (§7.2).
6. Stop active waiting; wait for TLS context init; **PUT** the string to Storage under `id` (§6.2). Upload errors
   are only shown in a dialog: timeout → **401201**; TLS certificate not issued for the host → **400004**
   (message contains the host); other → **401200**.
7. Exit (`main` calls `forceCloseApplication(0)` for every non‑websocket URL).

Uploads are serialised by a process‑wide lock (keep‑alive and result never interleave). For `selectcert` and
`batch` the result is uploaded **twice** (same content). For `selectcert` an `SSLHandshakeException` in the
operation's own upload is reported as **401200** and the second upload is skipped.

Parameter errors detected before the operation (e.g. 600104) are **not** uploaded: they are shown in a dialog and
the page times out (AS620024).

AutoScript side: polls the Retriever (§6.3) every 3 s (4 s on mobile); `ERR-06` = not yet available;
`#WAIT` (case‑insensitive prefix `#wait`) resets its give‑up counter; gives up after 11 (16 mobile) polls without
`#wait`.

### 5.4 Page‑side (AutoScript 1.10.1) timing and selection constants

These are not implemented by the app but define the envelope the app must work within:

| Item | Value |
|---|---|
| Candidate ports | `getRandomPorts(min,max)`: default range **49152–65535**; 3 distinct random ports (1 or 2 if the range is that small); `setPortRange(min,max)` clamps to 1024–65535 |
| WebSocket: first connection attempt | 3000 ms after opening the `afirma://websocket` URL |
| WebSocket: retries | `AUTOFIRMA_CONNECTION_RETRIES` = **15** rounds every `AUTOFIRMA_LAUNCHING_TIME` = **2000 ms**, each round opens `new WebSocket("wss://127.0.0.1:"+port)` for every port; then AS620017 |
| WebSocket: echo retries | every 2000 ms while the socket is not open (same counter) |
| WebSocket: `getresult` interval | 2000 ms after each `#wait` (no limit) |
| WebSocket: session id | one per page load (reused for all operations) |
| Service: echo probing | 2000 ms after launch, all ports in parallel; 15 attempts every 2000 ms; relaunch if a known port stops answering (counter < 7.5); then AS620020 |
| Service: request size threshold | 12 000 (IE) / 458 752 (Firefox) / 1 048 576 chars before fragmenting |
| Service: session id | new id at every app launch |
| Server mode: URL length limit | **2000** chars (above → upload envelope §4) |
| Server mode: polling | 3000 ms desktop / 4000 ms mobile; give up after 10+1 / 15+1 polls without `#wait` (AS620024) |
| Server mode: ids | `id` (= `rid`) new per operation; `fileid` new per upload; 20 chars, alphabet in §2.7 |
| Launch method | Chrome/iOS/Firefox‑Android: `location = url`; IE: `navigator.msLaunchUri`; others: hidden `<iframe id="iframeAfirma">`; Chrome‑Android server mode: `intent://…#Intent;scheme=afirma;package=es.gob.afirma;end` |
| Mode choice | §1 table; `setForceWSMode(true)` forces **server** mode (the name means "Web Service", not WebSocket) |

---

## 6. Intermediate server (Storage / Retriever) wire specification

Both servlets are deployed separately (`/afirma-signature-storage/StorageService`,
`/afirma-signature-retriever/RetrieveService` by AutoScript default) and share a directory of temporary files.

### 6.1 Server configuration (both)

File `intermediate_config.properties`, found in the directory named by system property
`clienteafirma.config.path`, else on the classpath. Values may contain `${sysprop}` placeholders.

| Key | Default | Meaning |
|---|---|---|
| `tmpDir` | `java.io.tmpdir` | directory holding one file per id |
| `expTime` | `60000` ms | files older than this (by mtime) are expired and deleted |
| `maxFileSize` | `0` (unlimited) | Storage: max size of the decoded `dat` (bytes, platform charset) |
| `debug` | `false` | `true` → never delete files, no size limit |

### 6.2 Storage — `StorageService` (`op=put`)

Request (as sent by the app, `IntermediateServerUtil.sendData`):
```
POST <stservlet path>  HTTP/1.1                    (any method except GET is treated as "body" mode)
Host: <host[:port]>
User-Agent: Java/<java.version>
Accept: */*
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded    (JDK default for POST bodies; not set by the code)
Content-Length: <n>

op=put&v=1_0&id=<id>&dat=<payload>
```
* The app appends `<payload>` **raw** (no percent‑encoding). Payloads are result strings (§7.1, URL‑safe Base64,
  `|`, `.`, `:`, digits) or error strings (§7.2, which contain spaces, `:`, `=`, non‑ASCII letters!) or `#WAIT`.
* Server parsing (POST): read whole body, `new String(bytes)` (platform charset), split on `&`, each `k=v` at the
  first `=` (values **not** decoded at this stage); then `dat` is `URLDecoder.decode(dat, "utf-8")`.
  Consequences: `+` in the payload becomes space; a literal `%` not followed by 2 hex digits makes the servlet
  throw (HTTP 500). Error strings with `&` would be truncated.
* GET mode: parameters via `request.getParameter` (`op=check` handled first: GET only).

Validation and responses (`text/plain; charset=utf-8`, header `Access-Control-Allow-Origin: *`, always HTTP 200):

| Condition | Body |
|---|---|
| GET with `op=check` | `OK` + line separator (`println`) |
| `op` missing | `ERR-00:=No se ha indicado código de operación` + EOL |
| `v` missing | `ERR-20:=No se ha indicado la versión de la sintaxis de la operación` + EOL |
| `op` ≠ `put` (case‑insensitive) | `ERR-01:=Código de operación no soportado` + EOL |
| `id` missing | `ERR-05:=No se ha proporcionado un identificador para los datos` + EOL |
| `id` contains `.`, `/` or `\` (or resolves outside `tmpDir`) | `ERR-06:=El identificador para los datos es inválido` + EOL |
| `dat` missing/empty | stores the text `ERR-02:=No se han proporcionado los datos de la operación` in the file (and answers `OK`) |
| decoded `dat` larger than `maxFileSize` (>0, not debug) | stores `ERR-07:=Los datos solicitados o enviados son inválidos` (answers `OK`) |
| file write failure | `ERR-18:=No se ha podido enviar la firma generada a la Web de origen` + EOL |
| success | `OK` (**no** line separator) |

The stored file `<tmpDir>/<id>` contains the decoded `dat` text (platform charset bytes), overwriting any previous
content. After each request, expired files are deleted. Error format: `ERR-NN` + `:=` + message (UTF‑8 text,
messages in Spanish with accents as shown).

The app ignores Storage response bodies (only HTTP/IO errors matter).

### 6.3 Retriever — `RetrieveService` (`op=get`)

Request (app side, `IntermediateServerUtil.retrieveData`): `POST <rtservlet>` body `op=get&v=1_0&id=<id>`.
AutoScript polls with `op=get&v=1_0&id=<id>&it=<n>` (`it` ignored by the server). Parameters are read with
`request.getParameter` (query or form body, URL‑decoded).

| Condition | Body (`text/plain; charset=utf-8`, CORS `*`, HTTP 200) |
|---|---|
| `op` missing | `ERR-00:=No se ha indicado código de operación` + EOL |
| `op=check` | `OK` + EOL |
| `v` missing | `ERR-20:=…` + EOL |
| `op` ≠ `get` (case‑insensitive) | `ERR-01:=Código de operación no soportado` + EOL |
| `id` missing | `ERR-05:=…` + EOL |
| `id` has `.`/`/`/`\` or escapes `tmpDir` | `ERR-06:=El identificador para los datos es inválido` + EOL |
| file absent, not a regular file, symlink, unreadable or expired | `ERR-06:=El identificador para los datos es inválido` + EOL (file deleted if it exists) |
| read error | `ERR-07:=Los datos solicitados o enviados son inválidos` + EOL |
| success | the file content + EOL (`println`, platform line separator: `\n` on Unix servers, `\r\n` on Windows) — **the file is deleted** (one‑shot read) |

Client rules (app, §4 step 3): a response is an error if `len > 8` and the first 8 bytes lower‑cased start with
`err-`. Decoders must tolerate the trailing EOL (Java's Base64 decoder skips it).

### 6.4 Active waiting (`aw=true`, direct mode only)

* Thread `ActiveWaitingThread`: after TLS init, loop: under the global upload lock PUT `dat=#WAIT` for the
  operation `id` to `stservlet`; sleep **10 000 ms**; repeat until interrupted. I/O errors are logged and ignored.
* Interrupted just before the final result upload. Because the Retriever deletes the file on each read and
  Storage files expire after `expTime` (60 s), the page sees `#WAIT` roughly every 10 s while the user works and
  keeps polling.

---

## 7. Responses, result formats and error codes

### 7.1 Success payloads (exact)

Notation: `B64U(x)` = URL‑safe Base64 **with** `=` padding; `B64S(x)` = standard Base64 with padding;
`C(x)` = cipher output (§8: DES `"<d>.<B64U>"`, AES `"<B64U>"`). Separators are literal ASCII.

| Operation | No cipher config | With cipher config (`key`/`cipher` present) |
|---|---|---|
| `sign`, `cosign`, `countersign`, `signandsave` | `B64U(certDER) "\|" B64U(signature) [ "\|" B64U(extra) ]` | `C(certDER) "\|" C(signature) [ "\|" C(extra) ]` |
| `selectcert` | `B64U(certDER)` | `C(certDER)` |
| `batch` | `B64S(resultUTF8) [ "\|" B64S(certDER) ]` (⚠ standard alphabet; result **first**) | `C(resultUTF8) [ "\|" C(certDER) ]` |
| `save` | `OK` | `OK` (never encrypted) |
| `load` | `name ":" B64S(content) *( "\|" name ":" B64S(content) )` | same (never encrypted) |

* `certDER` = DER of the **first certificate of the chain** (the signing certificate), not the chain.
* `extra` (sign family) is present only when the protocol **major** version ≥ 3 **and** the data were chosen by
  the user in the app's file dialog. Its plaintext is exactly
  `{"filename": "<file name>"}` (UTF‑8; note the space after the colon; the name is **not** JSON‑escaped).
  (Generic form for several keys: `{"k1": "v1", "k2": "v2"}` with `", "` separators.)
* `batch`: `resultUTF8` is the batch result document (§9.5/§9.6); the certificate is appended iff `needcert=true`.
* `load`: `name` is the bare file name (no path) and is not escaped (`:` or `|` in names break parsing); items in
  the dialog's selection order.
* Plugins with inline processors may replace the sign‑family format (out of scope).

### 7.2 Error strings

The format depends on the **protocol version in effect** (§11):

**Version ≥ 4.1** (`hasSupportTo(4.1)`: major > 4, or major = 4 and minor ≥ 1):
```
err-00:=AF<6-digit code> - <Java description>
err-11:=AF500001 - Operacion cancelada por el usuario          (cancellation only)
```
* `<Java description>` = the fixed Spanish description of the error code (Appendix A), **not localized**,
  copied byte‑for‑byte (some begin with a space, e.g. `AF200102 -  Error al cargar…`; a code without description
  renders `null`).
* AutoScript parses: prefix `err-` (case‑insensitive) and `:=`; if `" - "` is at offset 8 of the remainder the
  code is the first 8 chars (`AFnnnnnn`), else the whole remainder is the message. `err-11:` ⇒ cancellation.

**Version < 4.1** (legacy):
```
CANCEL                                  (cancellation)
SAF_NN: <localized message>             (everything else; Appendix B)
```
* `NN` from the AF→SAF association table (Appendix B); unmapped codes → `SAF_53` ("Error desconocido").
* The message is **localized** in the app's UI language (`es_ES` default; `en_US`, `ca_ES`, `gl_ES`, `eu_ES`,
  `va_ES`; or an imported language pack). Missing translation → `!<key>!`.

Separately, most failures also show a **modal error dialog** (unless the JVM system property
`es.gob.afirma.protocolinvocation.HeadLess=true`): title `Error` (≥4.1) or `Error AF<code>` (legacy);
text = localized `Error.<code>` entry, falling back to the group text (`Error.2XXXXX` …) or the Java
description. Which errors show a dialog:
* parameter errors (`ParameterException`) and unexpected exceptions → dialog **and** returned;
* operation errors raised inside the operation (`SocketOperationException`, e.g. no certificates, signer errors)
  → returned **without** dialog (batch keystore/certificate errors show one as well);
* cancellation → never a dialog.

Where the error string goes:
* sockets: it is the reply;
* direct launch: only errors raised inside the operation (and cancellation) are **uploaded** to Storage; parameter
  errors detected before the operation, and envelope download errors (except `save`, §4) are not uploaded.

### 7.3 Other literal tokens on the wire

| Token | Direction / mode | Meaning |
|---|---|---|
| `OK` | app→page (WS echo reply; service echo/last fragment; save result) | acknowledgement / save done |
| `SAVE_OK` | app→page (service mode `cmd`/`firm` save) | save done |
| `CANCEL` | app→page (legacy versions) | user cancelled |
| `#wait` | app→page (WS async) | operation in progress; page re‑asks with `getresult?idsession=<id>` |
| `#WAIT` | app→Storage (`aw=true`) | keep‑alive while the user works |
| `MORE_DATA_NEED` | app→page (service `fragment`) | send next fragment |
| `<n>` (decimal) | app→page (service `cmd`/`firm`) | number of response parts |
| `MEMORY_ERROR` | app→page (service, on `OutOfMemoryError`) | out of memory |
| `NULL` | (never produced by this app) | AutoScript treats it as unknown error |
| `ERR-NN:=…` | Storage/Retriever→client | servlet errors (§6) |

### 7.4 JS‑side interpretation (for compatibility testing)

AutoScript maps responses to callbacks as follows (all modes; details in Appendix C):
`CANCEL`/`err-11:` → `AOCancelledOperationException`/`AS500001`; `err-NN:=` → error with code `AFnnnnnn`;
`SAF_…` → `java.lang.Exception` with the raw string; `MEMORY_ERROR` → `AS620018` (WS) / `AS620021` (service);
sign success → `(signatureB64, certB64, extraText)` (URL‑safe converted back to standard); batch →
`(JSON.parse(base64decode(result)) || result, certB64)`; load → `name:b64` pairs; selectcert → cert.

---

## 8. Cipher specification

The cipher protects data that travels through the intermediate servers (and is also applied to socket replies if
the page sent `key`, which AutoScript only does in server mode).

### 8.1 Cipher configuration object

Built by the app from the URL (§3.1) and parsed with a lenient JSON parser (org.json: unquoted keys accepted):

| Source params | Config text (bytes, UTF‑8/platform) |
|---|---|
| `key=K` only | `{algo:"DES", key:"K"}` |
| `cipher=B` (Base64 JSON `J`) + `key=K` | `J` minus its last char, then `,legacydes:"K"}` |
| `cipher=B` only | `J` (⚠ then AES instantiation fails: missing `legacydes`, §8.3) |
| none | no cipher: plain encodings of §7.1 |

`algo` (`getString`; exact, case‑sensitive): `"AES"` → AES cipher; `"DES"` → DES cipher; missing `algo` or
invalid JSON → `JSONException` (sign family: **200117**; selectcert: **200200**; batch: **200400**; envelope
download: 4011xx). Any other `algo` value → **no cipher object** (⚠ QUIRK): results are then sent with the
*plain* encodings of §7.1 although the page expects ciphertext, and envelope decryption yields no data (generic
error). AutoScript's JSON (before the app appends `legacydes`):
`{"algo":"AES","key":"<B64S 32 bytes>","iv":"<B64S 16 bytes>","legDes":"<8 digits>"}` (the `legDes` key is
ignored by the app).

### 8.2 DES (legacy, `DesServerCipher`)

* Key: the 8 characters of `key` as bytes (platform charset; ASCII digits in practice) → DES key (parity bits
  ignored).
* Algorithm: **`DES/ECB/NoPadding`** over the data **zero‑padded** to a multiple of 8 bytes (no padding block
  added when already aligned).
* Output: `<d>` + `.` + `B64U(ciphertext)`, where `d = (8 − len % 8) % 8` (one decimal digit 0–7).
* Decryption: if the text has length > 2 and char[1] is `.`, `d = int(char[0])` and the Base64 part is
  `text[2..]`; else `d = 0` and the whole text is Base64. Base64 decoded after `-`→`+`, `_`→`/` (whitespace
  ignored). Plaintext = DES‑ECB‑decrypt, then drop the last `d` bytes.

Worked example (verified with OpenSSL): key `12345678`, plaintext `hello world` (11 bytes → padded with 5×`00`)
→ **`5.KNugLrX23UdgQtrr-lloeg==`**. Plaintext `abcdefgh` (8 bytes) → **`0.lNRDa8O1tpM=`**.

### 8.3 AES (`AesServerCipher`)

* Config fields (all read with `getString`, i.e. **all three are mandatory**, else `JSONException`): `key`
  (standard Base64 → 16/24/32 bytes; AutoScript uses 32), `iv` (standard Base64 → 16 bytes), `legacydes`
  (8‑char DES key used as fallback). Because of this, the Java app can only use AES when the page sent **both**
  `cipher` and `key` (AutoScript always does).
* Encryption: **`AES/CBC/PKCS5Padding`** (PKCS#7) with the given key and **the same IV for every field and every
  message**. Output `B64U(ciphertext)` (no `d.` prefix).
* Decryption (used for downloaded envelopes): text with `_`→`/`, `-`→`+`; AES‑CBC decrypt; **if that fails for any
  reason** (bad Base64 such as the `.` of a DES payload, bad padding…) retry with the DES `legacydes` key (§8.2)
  and, if that also fails, report the original AES error. This is required because AutoScript always uploads the
  **first** envelope of a page with DES even when it announces AES.

Worked example: key bytes `00 01 … 1f` (B64S `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`), IV `0f 0e … 00`
(B64S `Dw4NDAsKCQgHBgUEAwIBAA==`), plaintext `hello world` → **`fpqXEo7wtKRZNTE7CEMP2g==`**.
`cipher` param for this config (AutoScript style, legDes `12345678`):
`eyJhbGdvIjoiQUVTIiwia2V5IjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0iLCJpdiI6IkR3NE5EQXNLQ1FnSEJnVUVBd0lCQUE9PSIsImxlZ0RlcyI6IjEyMzQ1Njc4In0=`
(percent‑encode `=` etc. when placed in a URL).

### 8.4 Where the cipher is applied

* Each `|`‑separated field of sign/selectcert/batch results is encrypted **independently** (§7.1).
* Downloaded envelopes (§4) are decrypted as a whole.
* Not applied to: error strings, `CANCEL`, `OK`, `#WAIT`, save/load results.
* Encryption failures → **200100** (signature), **200101** (cert), **200116** (extra data), **200200**
  (selectcert), **200400**/**200401** (batch result/cert); cipher config unusable at sign time → **200117**.

### 8.5 Page side (for interoperability tests)

AutoScript generates the DES key as `zeroFill(random_u32 % 100000000, 8)` (8 decimal digits) and, in a secure
context, a WebCrypto AES‑CBC‑256 key + random 16‑byte IV. It decrypts each `|` field separately (AES first, DES
fallback); for DES it also strips 8 extra bytes from the **last** field to compensate the Retriever's trailing
line break (artefact of its Base64 decoder) — the app must therefore not add or remove anything itself.

---

## 9. Batch signing (client side)

### 9.1 Flow overview (`ProtocolInvocationLauncherBatch`)

```
afirma://batch?…  ──► params (§3.7) ──► version / mcv checks ──► keystore (§12.3) + certificate dialog / sticky
      │                                                              │ (headless=true → no progress dialog)
      ▼                                                              ▼
 jsonbatch=true ─┬─ localBatchProcess=true ─► LocalBatchSigner (§9.4)  ─┐
                 └─ else ──────────────────► BatchSigner.signJSON (§9.2)├─► resultString (UTF‑8)
 jsonbatch≠true ─────────────────────────────► BatchSigner.signXML (§9.3)┘
      ▼
 result = B64S|C(result) [ "|" B64S|C(certDER) if needcert ]   (§7.1)  → socket reply / Storage put
```

* `localBatchProcess=true` with an XML batch is **not** supported (goes to `signXML` with null URLs →
  `IllegalArgumentException` → **600420**).
* Exceptions: wrong PIN → certificate selection repeated restricted to the same certificate (sticky cleared);
  `IllegalArgumentException` → **600420** `INVALID_FORMAT_SIGN_BATCH_PARAM`; certificate encoding → **200114**;
  locked keystore → its code, sticky cleared; other `AOException` → its own code; anything else → **200412**
  (local) / **200410** (JSON) / **200411** (XML), with an error dialog. No certificates → **504001** (dialog).
* Signature algorithm per item: the batch `algorithm` digest combined with the key type (§3.4 step 13).

### 9.2 JSON batch against a batch server (`BatchSigner.signJSON`)

**Batch definition** (sent by the page in `dat`, Base64url of the UTF‑8 JSON; built by AutoScript
`createBatch`/`addDocumentToBatch`/`signBatchProcess`):
```json
{
  "algorithm": "SHA256withRSA",
  "format": "XAdES",
  "suboperation": "sign",
  "extraparams": "<B64S(properties text)>",
  "singlesigns": [
    { "id": "<unique id>", "datareference": "<data or reference>",
      "format": "…", "suboperation": "…", "extraparams": "<B64S>" }
  ],
  "stoponerror": false
}
```
| Field | Req. | Notes |
|---|---|---|
| `algorithm` | **client‑required** | read by the app (missing or JSON invalid → **600419** `MALFORMED_JSON_BATCH`). Digest name or `<digest>with<RSA\|ECDSA>`. |
| `format` | server‑required | batch default: `CAdES`, `XAdES`, `PAdES`, `FacturaE`, `NONE`, `CAdES-ASiC-S`, `XAdES-ASiC-S` (server rules). |
| `suboperation` | no | `sign` (default), `cosign`, `countersign`. |
| `extraparams` | no | standard Base64 of a properties text; per‑item value overrides. |
| `stoponerror` | no | JSON boolean (strings `"true"`/`"false"` tolerated by org.json). |
| `concurrenttimeout` | no | documented but **ignored** by every component. |
| `singlesigns[].id` | yes | used as `SignatureId`, must be unique (AutoScript checks). |
| `singlesigns[].datareference` | yes | data in a form the server's DocumentManager understands (Base64, URL, id…). |

**Step 1 — presign**: `POST <batchpresignerurl>` (URL used verbatim + `?` + body, see §12.6), body:
```
json=<B64U(batch JSON bytes as received)>&certs=<B64U(cert1 DER)>;<B64U(cert2 DER)>;…
```
(full chain, separator **`;`**, values not percent‑encoded). TLS‑trust import dialog + one retry allowed.
Errors: HTTP 400 → **600417**; other 4xx → **401501**; 5xx → **300601**; timeout → **401502**; other I/O →
**401500**.

**Presign response** (`application/json`):
```json
{ "td": { "format": "XAdES",
          "signs": [ { "signinfo": [ { "id": "<singlesign id>", "signid": "<opt>",
                                       "params": { "PRE": "<B64S>", "NEED_PRE": "true", "…": "…" } } ] } ] },
  "results": [ { "id": "<singlesign id>", "result": "ERROR_PRE", "description": "<opt>" } ] }
```
* `td` and `results` optional; `td` may also be the flat form `{"format":…,"signinfo":[…]}`. All `params` values
  must be JSON strings. `results[].result` must be a valid result name (§9.5).
* Neither present → return `{"signs":[]}`. Only `results` → return `{"signs":[{"id":…,"result":…[,"description":…]}…]}`
  without calling the postsigner (org.json compact serialisation).
* If `results` present: in the batch JSON, for every `singlesigns[i]` whose `id` equals a result id, remove
  `datareference`, `format`, `suboperation`, `extraparams` and add `"result": <name>` and `"description"` (if
  non‑null); re‑serialise compactly (org.json `toString()`; key order not guaranteed) → new `json` value.

**Step 2 — client PKCS#1** (§10.4) over every `TriSign` of `td` (no extra params).

**Step 3 — postsign**: `POST <batchpostsignerurl>` body:
```
json=<B64U(batch or rewritten batch)>&certs=<chain ;‑separated>&tridata=<B64U(UTF‑8 tridata JSON)>
```
`tridata` JSON = `{"format":"<td.format, if any>","signinfo":[{"id":…,"signid":…(if any),"params":{…all params incl. PK1…}}]}`.
No TLS import dialog. Errors: 400 → **600418**; 4xx → **401601**; 5xx → **300602**; timeout → **401602**;
I/O → **401600**.

**Result**: the postsign response body, verbatim (UTF‑8), e.g.
`{"signs":[{"id":"a1", "result":"DONE_AND_SAVED"},{"id":"a2", "result":"ERROR_PRE", "description":"…"}]}`
(server‑built text; note `", "` spacing). Signatures are **not** returned (stored server side).

### 9.3 XML batch (legacy) against a batch server (`BatchSigner.signXML`)

Batch definition (Base64url in `dat`):
```xml
<signbatch stoponerror="true|false" algorithm="SHA256" [concurrenttimeout="N"]>
  <singlesign id="ID">
    <datasource>URL or Base64 data</datasource>
    <format>XAdES|CAdES|PAdES|…</format>
    <suboperation>sign|cosign|countersign</suboperation>
    <extraparams>B64S(properties)</extraparams>
    <signsaver><class>es.gob.afirma.signers.batch.SignSaverFile</class><config>B64S(properties)</config></signsaver>
  </singlesign>
</signbatch>
```
* Client reads only the root (`signbatch`, case‑insensitive) attribute `algorithm` (missing →
  `IllegalArgumentException` → 600420; unparsable XML → **600503** `MALFORMED_XML_BATCH`).
* Presign: `POST <batchpresignerurl>` body `xml=<B64U(batch)>&certs=<chain ;>`; response = **raw TriphaseData
  XML** (§10.2, *not* Base64). Errors: 400 → **600501**; 4xx → **401701**; 5xx → **300701**; timeout → **401702**;
  I/O → **401700**.
* Client PKCS#1 (§10.4).
* Postsign: body `xml=<B64U(batch)>&certs=<chain ;>&tridata=<B64U(UTF‑8 of TriphaseData XML, §10.2)>`. Errors:
  400 → **600502**; 4xx → **401801**; 5xx → **300702**; timeout → **401802**; I/O → **401800**.
* Result: response body verbatim, typically
  `<signs><sign id="ID"><result>OK|KO|NP</result><reason>…</reason></sign>…</signs>`.
* The server in this repository no longer provides XML batch services (only `/presign` and `/postsign` for
  JSON); legacy servers exposed `/BatchPresigner` and `/BatchPostsigner`.

### 9.4 Local (monophase) JSON batch (`localBatchProcess=true`)

Parsing (`JSONBatchManager.parseBatchConfig`) of the JSON in `dat`:
* Invalid JSON → **200412**. Any interpretation error → **600419** (`MALFORMED_JSON_BATCH`).
* `stoponerror` (default false); `suboperation` default `sign` (case‑insensitive `sign|cosign|countersign`;
  unknown → failure later → 200412); `format` **required**; `algorithm` **required**; `extraparams` optional.
* Each `singlesigns[]`: `id` required; `datareference` required and must be **standard Base64 of the actual data**
  (no URLs, no URL‑safe alphabet); per‑item `suboperation`/`format`/`extraparams` override.
* `extraparams` decoding: standard Base64 → UTF‑8 text → `trim()` → replace the two‑character sequence `\n` with
  a real newline → properties parse; empty → none.

Signing (sequential, `LocalBatchSigner`):
* For each item: compose algorithm from key type (failure **200110**); signer for `format` (unknown **600105**;
  `auto` → detection, failure **501009**); extra params copy + `headless=true`; sign/cosign/countersign
  (`target=tree` → tree, else leaves). Errors converted to per‑item failures (codes as in §3.4 step 14; other →
  **200412**).
* `stoponerror=true`: at the first failure **all previous results become `SKIPPED` and lose their signature**,
  the failing item becomes `ERROR_PRE` with `description` = error message (or the 6‑digit code if no message),
  and all later items are `SKIPPED` without being attempted.
* Without stoponerror: failures are `ERROR_PRE` and processing continues.

Result (org.json compact, key order unspecified):
```json
{"signs":[{"id":"a1","result":"DONE_AND_SAVED","signature":"<B64S(signature)>"},
          {"id":"a2","result":"ERROR_PRE","description":"…"},{"id":"a3","result":"SKIPPED"}]}
```

### 9.5 Result values

`NOT_STARTED`, `DONE_AND_SAVED`, `DONE_BUT_NOT_SAVED_YET`, `DONE_BUT_SAVED_SKIPPED`, `DONE_BUT_ERROR_SAVING`,
`ERROR_PRE`, `ERROR_POST`, `SKIPPED`, `SAVE_ROLLBACKED` (server JSON). Local batch uses `DONE_AND_SAVED`,
`ERROR_PRE`, `SKIPPED`. XML batch: `OK`, `KO`, `NP`.

### 9.6 Server‑side stop‑on‑error semantics (for reference)

Presign: after an error with `stoponerror`, remaining items → `SKIPPED`. Postsign: items that came back with a
`result` count as errors; an error with `stoponerror` → remaining `SKIPPED` and every `DONE_AND_SAVED` is rolled
back (`SAVE_ROLLBACKED`). Concurrent mode (server config) uses a thread pool with a per‑phase timeout; same JSON
shapes. Server limits (`batch.maxSize`, `batch.maxDocuments`, `batch.maxReferenceSize`) → HTTP 400.

### 9.7 AutoScript side

* `signBatchProcess(stopOnError, preUrl, postUrl, certFilters, ok, err)` → `afirma://batch` with
  `jsonbatch=true`, `needcert=true`, `properties=B64(certFilters)`, `dat=B64U(JSON)`, optional
  `localBatchProcess=true`. Success callback receives `(JSON.parse(base64decode(result)), certB64)`.
* `signBatch(batchB64, preUrl, postUrl, params, ok, err)` → XML batch (`needcert=true`, no `jsonbatch`); callback
  gets the Base64 result. (In server mode this JS path throws a ReferenceError — JS bug.)

---

## 10. Three‑phase (trifásica) signing client protocol

Triggered when `format` is a triphase format (table below) and the extra params contain
`serverUrl=<https://…/afirma-server-triphase-signer/SignatureService>`.

### 10.1 Format mapping and requirements

| `format` (afirma://, case‑insensitive) | `format` sent to server | Operations |
|---|---|---|
| `CAdEStri` | `CAdES` | sign, cosign, countersign |
| `CAdES-ASiC-S-tri` | `CAdES-ASiC-S` | sign only (others → 600002) |
| `XAdEStri` | `XAdES` | sign, cosign, countersign |
| `XAdES-ASiC-S-tri` | `XAdES-ASiC-S` | sign, cosign |
| `FacturaEtri` | `FacturaE` | sign |
| `PAdEStri`, `Adobe PDF TriPhase` | **`pades`** (lower case) | sign (cosign = sign); countersign unsupported |
| `NONEtri` | `NONE` | sign |

* Missing/invalid `serverUrl` (not a valid URL) or missing key/chain → `IllegalArgumentException` → **600121**.
* Data required except XAdES `sign` with `format=XAdES Externally Detached` or `useManifest=true` in extra params.
* Before calling the signer the app: removes `profile`, expands extra params (policies), composes `algo` =
  `<digest>with<RSA|ECDSA|DSA>` from the key type (e.g. `SHA256withRSA`), applies `servicetimeout` as HTTP read
  timeout (sign/cosign/countersign only). Countersign target from extra param `target` (`tree`/else `leafs`) is
  put back into extra params as `target=tree|leafs`.

### 10.2 TriphaseData XML (session) — exact serialisation

```
<xml>\n
 <firmas format="FMT">\n            ← ` <firmas>\n` when no format (single‑sign sessions have none)
  <firma Id="ID" signid="SID">\n    ← each attribute only if present
   <param n="KEY">VALUE</param>\n   ← one per parameter (map iteration order, unspecified)
  </firma>\n
 </firmas>\n
</xml>                              ← no trailing newline, no XML declaration, values NOT escaped
```
Bytes = the string in the platform charset (ASCII content). Parsing rules (both directions): secure DOM; root name
not checked; first element child must be `firmas` (case‑insensitive) with optional `format`; each element child =
one sign with attributes `Id` (case‑sensitive) and optional `signid`; each element child of a sign = one param with
attribute `n` and text content **trimmed**.

### 10.3 Single‑sign wire protocol (client ↔ `SignatureService`)

Every call is an HTTP **POST** to `serverUrl` whose body is a raw `k=v&…` string (values are URL‑safe Base64 or
tokens, **never percent‑encoded**; the server URL‑decodes each value). Field order as emitted (cosmetic, but keep
it for byte parity):

**Presign** (`op=pre`):

| Format | Body |
|---|---|
| CAdES, CAdES‑ASiC‑S | `op=pre&cop=<cop>&format=<fmt>&algo=<algo>&cert=<chain>&doc=<B64U(data)>[&params=<B64U(props)>]` — `serverUrl` and `documentId` are **removed from the extra params** first (and stay removed for the postsign) |
| XAdES, XAdES‑ASiC‑S, FacturaE | `op=pre&cop=<cop>&format=<fmt>&algo=<algo>&cert=<chain>[&doc=<B64U(data)>][&params=<B64U(props)>]` — on a copy without `validatePkcs1` and `serverUrl` |
| PAdES | `op=pre&cop=sign&format=pades&algo=<algo>&cert=<chain>&doc=<B64U(data)>[&params=<B64U(props)>]` — nothing removed (`serverUrl` **is** sent inside `params`) |
| NONE | `op=pre&cop=sign&format=NONE&algo=<algo>&cert=<B64U(leaf)>&doc=<B64U(data)>` — no `params` |

* `<cop>` ∈ `sign`, `cosign`, `countersign`.
* `<chain>` = `B64U(DER)` of every certificate of the chain joined with **`,`**; only the leaf if the extra param
  `includeOnlySignningCertificate=true` (sic) or extra params are null.
* `<B64U(props)>` = URL‑safe Base64 of the properties written by Java `Properties.store(writer, "")` in UTF‑8:
  a first line `#`, a second line `#<Date.toString()>`, then `key=value` lines with Java escaping, platform line
  separator, arbitrary order. Omitted when empty. (Any valid `.properties` text is accepted by the server.)
* `doc` = URL‑safe Base64 of the bytes received in `dat` (document, existing signature for multi‑sign, or a
  document reference understood by the server's DocumentManager).

**Presign response**: `B64U(TriphaseData XML)` (no newline) or an error text `ERR-…`. Client checks:
1. body length ≤ 8 → **300401** (not for NONE);
2. first 8 bytes start with `ERR-` → server error (§10.5) (not for NONE);
3. URL‑safe Base64 decode + TriphaseData parse → failure **300401**.
HTTP errors: 400 → **600701**; other 4xx → **401301**; 5xx → **300400**; timeout → **401302**; I/O → **401300**
(NONE: any HTTP error → 300400). TLS import dialog + retry allowed.

**Client signing**: §10.4. Then `session = B64U(TriphaseData XML of the signed data)`.

**Postsign** (`op=post`):

| Format | Body |
|---|---|
| CAdES, CAdES‑ASiC‑S | `op=post&cop=<cop>&format=<fmt>&algo=<algo>&cert=<chain>[&params=<B64U(props)>]&session=<session>&doc=<B64U(data)>` (`doc` always sent) |
| XAdES family | `op=post&cop=<cop>&format=<fmt>&algo=<algo>&cert=<chain>&session=<session>[&doc=<B64U>][&params=<B64U(props)>]` — connect timeout = extra param `servicetimeout` if numeric; no TLS import dialog |
| PAdES | `op=post&cop=sign&format=pades&algo=<algo>&cert=<chain>&doc=<B64U(data)>&session=<session>[&params=<B64U(props)>]` |
| NONE | `op=post&cop=sign&format=NONE&algo=<algo>&cert=<B64U(leaf)>&doc=<B64U(data)>&session=<session>` |

**Postsign response**: `OK NEWID=<B64U(result)>` + line separator, or `ERR-…`. Client: length ≤ 8 → **300407**;
`ERR-` prefix → §10.5; trim; must start with `OK` else **300405** ("La firma trifasica no ha finalizado
correctamente: …"); decode `text.substring(9)` (after `OK NEWID=`) as URL‑safe Base64 (failure **300407**). The
decoded bytes are **the signature** returned to the page like a local signature (§7.1). (With a file‑system
DocumentManager the server returns a *standard* Base64 file name → may fail to decode; ⚠ server‑side quirk.)
HTTP errors: 400 → **600702**; 4xx → **401401**; 5xx → **300404**; timeout → **401402**; I/O → **401400**.

### 10.4 Client PKCS#1 over a TriphaseData (`TriphaseDataSigner.doSign`)

```
if number of <firma> < 1                → error 300402 PRESIGNS_NOT_FOUND
for each <firma> (in order):
    PRE = param "PRE"                    → missing: error 300401 ("El servidor no ha devuelto la prefirma numero i")
    bytes = Base64.decode(PRE)           ← STANDARD alphabet
    sig   = Sign(<digest>with<RSA|ECDSA|DSA>, privateKey, bytes)   ← RSASSA‑PKCS1‑v1_5 over the raw PRE bytes
                                                                     (hash computed by the signature primitive);
                                                                     ECDSA → DER‑encoded (r,s)
    verify sig with the leaf certificate's public key → mismatch 200112 / verification error 200113
    add param "PK1" = Base64std(sig)
    if param NEED_PRE is absent or not "true" → remove param "PRE"
everything else (Id, signid, other params such as NEED_DATA, BASE, ENCODING, TIME, PID, CACHE_ID, HMAC,
PK1_DECODED) is echoed back unchanged.
```
NONE format: signs only the first `<firma>` and never removes `PRE`.

Server presign payload per format (informative; the client only uses `PRE`/`NEED_PRE`): CAdES `PRE` = DER signed
attributes (`NEED_PRE=true`, `NEED_DATA` when implicit); CAdES countersign one `<firma>` per target signer;
XAdES/FacturaE one `<firma>` per SignedInfo, `BASE`/`ENCODING` on the first, `PK1_DECODED=true` for (EC)DSA (the
server converts DER→raw itself); PAdES `PRE`, `NEED_PRE`, `TIME`, `PID`; NONE `PRE` only. Optional `CACHE_ID`
(server cache) and `HMAC` (server integrity code) params.

### 10.5 Server error grammar and client mapping

Server text: `ERR-<n>: <message>[: <exception>]`, and for user‑intervention requests
`ERR-21:<requestCode>: Se requiere intervencion del usuario: <exception>`.

Client parser: `sep = indexOf(':')`.
* If it starts with `ERR-21:` → `code` = text between the first and second `:`; mapped to a
  "runtime config needed" request (table) → the app asks the user (or fails if `headless=true`/denied) and, on
  confirmation, **re‑runs the whole three‑phase operation** with the extra param set.

| `ERR-21` code | Formats | Extra param set on "yes" |
|---|---|---|
| `signingLts` | CAdES, XAdES | `allowSignLTSignature=true` |
| `signingLtsPossible` | XAdES | `allowSignLTSignature=true` |
| `xPathNotFound` | XAdES | `allowXadesEnvelopedWithoutXPath=true` |
| `agePolicyIncompatibilitySign`, `…Cosign`, `…CounterSign` | XAdES | `avoidAGEPolicyIncompatibilities` (custom preparation) |
| `signingCertifiedPdf` | PAdES | `allowSigningCertifiedPdfs=true` |
| `signingPdfWithUnregisteredSigns` | PAdES | `allowCosigningUnregisteredSignatures=true` |
| `signingModifiedPdfForm` | PAdES | `allowModifiedForm=true` |
| `pdfShadowAttackSuspect` | PAdES | `allowShadowAttack=true` |
| `pdfpasswordprotected`, `pdfbadpassword` | PAdES | password prompt → `ownerPassword=<pwd>`, `userPassword` removed |

* Otherwise: `ERR-<n>` → error code below (presign / postsign); unknown `n` → **300451** / **300452**. If the
  third `:`‑separated token names a Java exception class of the "runtime config needed" family it is re‑created as
  a *denied* request (error without prompt).

| `n` | Presign code | Postsign code | Server meaning |
|---|---|---|---|
| 1 | 300409 | 300430 | operation missing |
| 2 | 300410 | 300431 | document id missing |
| 3 | 300411 | 300432 | algorithm missing |
| 4 | 300412 | 300433 | format missing |
| 5 | 300413 | 300434 | certificate missing |
| 6 | 300414 | 300435 | invalid extra params (also invalid `session` Base64) |
| 7 | 300415 | 300436 | certificate not X.509 |
| 8 | 300416 | 300437 | unsupported format |
| 9 | 300417 | 300438 | presign failure |
| 10 | 300418 | 300439 | document store failure |
| 11 | 300419 | 300440 | unknown operation |
| 12 | 300420 | 300441 | postsign failure |
| 13 | 300421 | 300442 | invalid sub‑operation |
| 14 | 300422 | 300443 | document retrieval failure (⚠ server prints it without the `ERR-` prefix → client reports 300401/300405) |
| 15 | 300423 | 300444 | invalid session data |
| 16 | 300424 | 300445 | verification code generation |
| 17 | 300425 | 300446 | verification code check |
| 18 | 300426 | 300447 | integrity error |
| 19 | 300427 | 300448 | invalid operation data |
| 20 | 300428 | 300449 | unsupported algorithm (e.g. `MD*`) |

### 10.6 Server behaviour relevant to clients (`SignatureService`)

* Parameters are read **only from the POST body** (UTF‑8, `&`/first `=`, values URL‑decoded); GET does not work.
* Errors are HTTP 200 bodies `ERR-…` (body read failure → HTTP 400). CORS header from config (default `*`).
* `algo` missing → `SHA512withRSA`; `format=auto` supported server‑side; `headless=true` forced.
* With HMAC verification configured, `PRE` must be echoed (servers set `NEED_PRE=true` accordingly).
* Endpoints in this repo: `/SignatureService`, `/presign` and `/postsign` (JSON batch), `/version`.

### 10.7 Sequence example (CAdES)

```
page → app : afirma://sign?op=sign&format=CAdEStri&algorithm=SHA256withRSA&properties=B64(serverUrl=https://s/afirma-server-triphase-signer/SignatureService)&dat=…
app        : certificate selection
app → srv  : POST /SignatureService  op=pre&cop=sign&format=CAdES&algo=SHA256withRSA&cert=MIIF…,MIIG…&doc=SG9sYQ==
srv → app  : PHhtbD4KIDxmaXJtYXM-CiAgPGZpcm1hIElkPSIuLi4iPgogICA8cGFyYW0gbj0iUFJFIj4uLi48L3BhcmFtPgo…
app        : PK1 = B64S(RSA‑PKCS1(SHA‑256, B64S⁻¹(PRE)))   (PRE kept because NEED_PRE=true)
app → srv  : POST /SignatureService  op=post&cop=sign&format=CAdES&algo=SHA256withRSA&cert=…&session=<B64U(xml)>&doc=SG9sYQ==
srv → app  : OK NEWID=MIAGCSqGSIb3DQEHAqCAMIACAQEx…\n
app → page : <B64U(cert)>|<B64U(signature)>
```

---

## 11. Protocol versions and compatibility

### 11.1 Version history (`ProtocolVersion`)

| Version | Introduced |
|---|---|
| `0` | initial (also the default when nothing is declared) |
| `1` | changes in the cipher of data sent through the intermediate server |
| `2` | changes in the encoding of the keystore parameter (`ksb64`) |
| `3` | sign results include the selected file name (`extra` field) |
| `4` | additional WebSocket security (localhost check, `idsession`) |
| `4.1` | new error codes (`err-NN:=AFnnnnnn - …`) and asynchronous WebSocket tasks (`#wait`/`getresult`) |

Rules: two versions are *compatible* iff same major. `hasSupportTo(x)` iff `major > x.major` or
(`major == x.major` and `minor ≥ x.minor`). Parsing/rendering per §2.8.

### 11.2 How the effective version is determined

1. Socket channel: from the `v` of `afirma://websocket|service` (trimmed; invalid → 0).
   Direct launch: from the operation's `ver` (invalid → 0; absent → `"0"`).
2. **Upgrade rule** (`reviewProtocolVersion`): if major == 4 and `jvc > 3` → **4.1**. (AutoScript 1.10.x sends
   `v=4`/`ver=4` and `jvc=4`, so the effective version is always 4.1.)
3. Channel acceptance: WebSocket accepts majors {3, 4}; service accepts {1, 2, 3}.
4. Operation acceptance (`isCompatibleWith`): the app supports **4.1, 3, 2, 1** → any major in {1, 2, 3, 4} is
   accepted; major 0 or ≥ 5 → **620011** `UNSUPPORTED_PROTOCOL_VERSION` (legacy text `SAF_21: La versión de
   Autofirma instalada no es compatible con este trámite. Actualice a la última versión disponible.`).

### 11.3 Version‑dependent behaviour

| Behaviour | Condition |
|---|---|
| error string format `err-NN:=AF…` vs `SAF_NN:`/`CANCEL` | ≥ 4.1 |
| error dialog title `Error` vs `Error AF<code>` | ≥ 4.1 |
| `extra` filename field in sign results | major ≥ 3 |
| WebSocket V4 server (host/session checks) vs legacy v3 server | major 4 vs 3 |
| async WebSocket (`#wait`) | `jvc > 3` (independent of minor) |

### 11.4 Minimum client version (`mcv`) and app version

`mcv` is compared with the app version text **`1.10`** (Rust: report the same text for parity, or the Rust
version if it is ≥ the Java one — decision for the product). Algorithm (`Version.greaterThan`):
* Split on `.`; all parts but the last must be integers (else exception → generic error); the last part may be
  `digits` followed by a text suffix (e.g. `10-beta`, `10 RC`). Missing text → suffix `""`.
* Compare integer parts pairwise; first difference decides. If all equal, the one with **more** parts is greater.
* Same parts: equal suffixes (case‑insensitive) → not greater; a suffix starting with a space char ranks **below**
  no suffix / non‑space suffix; otherwise lexicographic case‑insensitive comparison.
* Error **500005** `MINIMUM_VERSION_NON_SATISTIED` iff `mcv > appVersion`.

### 11.5 JavaScript version code (`jvc`)

| `jvc` | Effect |
|---|---|
| absent/invalid | treated as 1 |
| < 1 | warning dialog "insecure JavaScript version", continue |
| > 3 | v4 → v4.1; WebSocket async mode |

---

## 12. OS‑specific behaviour, sticky signatory, keystore selection, locale, logs

### 12.1 Process model and OS integration

* One process per `afirma://` URL. Direct‑launch processes exit right after the operation; WebSocket processes
  live until the socket closes; service processes until 90 s idle.
* Windows: registry `HKCR\afirma` (`URL Protocol`) → `"<install>\Autofirma.exe" "%1"`.
* Linux: `afirma.desktop` with `MimeType=x-scheme-handler/afirma;` and `Exec=/usr/bin/autofirma %u`.
* macOS: a native launcher app (`Autofirma.app`, bundle id `es.gob.afirma.simpleafirma.osx`, URL scheme `afirma`)
  receives the Apple Event `kAEGetURL`, and spawns
  `<bundle>/Contents/Resources/Home/bin/java -Xms1024M -Xmx2048M -Djdk.tls.maxHandshakeMessageSize=65536 … -jar
  <bundle>/Contents/Resources/JAR/autofirma.jar <url>` (cwd = home), then terminates itself after 5 s. Thus also
  one JVM per URL. In‑app, macOS additionally: overrides the "About" menu, grabs focus with AppleScript
  `tell me to activate` before every dialog, and in service mode kills `ps` entries matching the `idsession`
  when the idle timer expires.
* Android/iOS apps (different products) are launched by AutoScript with `intent://<op>?…#Intent;scheme=afirma;package=es.gob.afirma;end`
  (Chrome/Android) or `afirma://` and only use the intermediate‑server mode.
* JMulticard (DNIe/CERES smart cards) enabled/disabled per preference before each launch.
* At protocol start‑up a background task pre‑loads the OS keystore or the store configured for browser
  invocations (unless it is a file or smart‑card store); operations reuse it if they need the same store.

### 12.2 Sticky signatory (certificate caching)

* Process‑wide single slot `stickyKeyEntry` (private key + chain) — lives only as long as the process, i.e. only
  meaningful in WebSocket/service mode where one process serves several operations.
* `sign`/`cosign`/`countersign`: if `sticky=true` and `resetsticky≠true` and the slot is filled → use it (no
  dialog). After the certificate is chosen, the slot is **set** to that key if `sticky=true`, else **cleared**.
  Wrong PIN → retried with a fresh keystore restricted to the same certificate. Locked keystore → slot cleared.
* `signandsave`: same reuse rule; after signing, slot set if `sticky` else cleared.
* `selectcert`, `batch`: same reuse rule; when a dialog is shown, slot set if `sticky` else cleared.
* AutoScript `setStickySignatory(true)` sends `sticky=true`; `setStickySignatory(false)` after `true`, and
  `setKeyStore(…)`, make the next call send `resetsticky=true`. In server mode on desktop AutoScript **emulates**
  sticky by adding `filters=encodedcert:<B64 cert>` and `headless=true` to `properties` (the app sees no `sticky`).

### 12.3 Keystore selection precedence (sign family, selectcert, batch)

1. If the user switched to another keystore in the certificate dialog earlier **in this process** (in‑memory
   "last selected keystore", not persisted) → that one.
2. Else if preference "use default store in browser calls" is on → the configured default store (unless it is
   the "system default" marker).
3. Else the store named by `keystore`/`ksb64` (§2.5).
4. If none → OS default: Windows `WINDOWS`, macOS `APPLE`, Linux `SHARED_NSS` (Solaris `MOZ_UNI`).
Library path: if rule 2 applied and the store is PKCS#12/PKCS#11 → preference "local keystore path"; else the
`:LIB` part of the parameter. The certificate dialog lets the user switch stores (unless the filter
`disableopeningexternalstores` is present); default filter when none given: hide expired certificates.

### 12.4 `setLocale`, `getCurrentLog`, `echo`, `checkTime`

These AutoScript functions **never reach the app**:
* `setLocale(locale)` only changes AutoScript's own dialog texts (`es_ES`, `gl_ES`, `va_ES`, `ca_ES`, `eu_ES`,
  `en_US`). The app's messages follow the app/OS language.
* `getCurrentLog(ok, err)` always fails locally (`java.lang.UnsupportedOperationException`,
  "El metodo JavaScript no se encuentra operativo", `AS500010`). There is no log‑retrieval operation in the
  protocol.
* `echo()` returns `"Cliente JavaScript"` locally. (`echo=` on sockets is the transport handshake, §5.)
* `checkTime()` compares the browser clock with an HTTP `Date` header; no app involvement.
* There is no `getversion` operation; version negotiation is only via `v`/`ver`/`jvc`/`mcv`.

### 12.5 Progress dialogs and headless operation

* `dlgload=false` in the launch URL hides the "processing" pop‑ups for the process.
* Extra param `headless=true` suppresses progress dialogs, makes certificate selection automatic when possible
  and makes any operation that needs user confirmation/password fail.
* JVM property `es.gob.afirma.protocolinvocation.HeadLess=true` suppresses error dialogs.
* JVM system property `AFIRMA_SHOW_DATA_TO_SIGN=true` (Java `Boolean.getBoolean`, not an environment variable)
  shows a debug dialog with the data to sign (sign operation only).

### 12.6 Outbound HTTP client behaviour (Storage, Retriever, `dat` URLs, triphase/batch servers)

* Java `HttpURLConnection` semantics (header list in §6.2; full detail in `07-core.md` §9). The code also tries to
  set `Host`, `Origin` and `Connection` headers, but the JDK silently drops these "restricted" headers, so **no
  `Origin` header is sent** and `Host`/`Content-Length` are the JDK's own. For POST/PUT the part after the first
  `?` of the URL is sent as the body (default content type `application/x-www-form-urlencoded`); the part after a
  *second* `?` would be lost. Userinfo in the URL → `Authorization: Basic`.
* Status 4xx/5xx → error (body kept for diagnostics). No automatic retries except the TLS‑trust import dialog.
* Default timeouts: JDK defaults (infinite) unless `servicetimeout` (read timeout, process‑wide sticky).
* Proxy: system proxy, bypassed for loopback hosts.
* Cookies: a global in‑memory cookie jar accepting all cookies (session affinity between presign/postsign).
* TLS: OS/JDK trust + AutoFirma's own trust store (if allowed by admin preference). Preference "secure
  connections" off → certificate validation disabled. Preference "secure domains list" (comma separated; `*x*`
  contains, `*x` suffix, `x*` prefix, exact otherwise) → validation disabled for matching hosts. On a handshake
  failure (and if allowed: not `headless`, not `sslOmitImportationDialog`, admin allows auto‑import) the app
  offers to import the server certificate into its trust store and retries once.
* If the server certificate is not valid for the host → **400004** with the host name.

---

## 13. Consolidated quirks and ambiguities

Java app (must be reproduced for byte compatibility unless marked MAY fix):

| # | Item | Section |
|---|---|---|
| Q1 | Query values are `URLDecoder`‑decoded: `+` → space; servlet URLs are decoded **twice**; malformed `%` escapes throw an uncaught exception. | 2.1, 2.6 |
| Q2 | Java Base64 decoder silently drops an unpadded trailing quartet and stops at the first `=`. | 2.2 |
| Q3 | `dat` starting with `http(s)://`/`ftp://` is downloaded by the app (no host restriction). | 2.3 |
| Q4 | `ksb64` decoded without URL‑safe normalisation; failures silently ignored. | 2.5 |
| Q5 | Invalid/absent `idsession` disables session checks instead of rejecting. | 2.7 |
| Q6 | `servicetimeout` errors reuse code 600009; `stservlet` errors in sign/selectcert/save reuse batch codes 6004xx. | 3.1, 3.4 |
| Q7 | The crypto operation of `sign`/`cosign`/`countersign` comes from the `op` query parameter, not from the URL host. | 3.4 |
| Q8 | `signandsave` rejects ECDSA algorithm names and ignores `servicetimeout`. | 3.5 |
| Q9 | `selectcert` and `batch` results are uploaded twice in server mode. | 3.6, 5.3 |
| Q10 | `load` cannot work in server mode (no Storage URL → generic error 200600). | 3.9 |
| Q11 | XML envelope: values URL‑decoded (corrupts raw `+`); whitespace between elements is fatal; XML errors reported as generic op errors. | 4.1 |
| Q12 | JSON envelope parser unreachable. MAY fix (sniff `{`). | 4.2 |
| Q13 | WebSocket server binds all interfaces; only V4 checks the peer is `127.0.0.1`. | 5.1 |
| Q14 | Legacy v3 WebSocket passes protocol version 0 → every operation fails with 620011. MAY fix. | 5.1.4 |
| Q15 | Service socket rejects `v=4` (what AutoScript 1.10.1 sends) → service mode unusable with current JS. MAY fix (accept 4). | 5.2.1, 11.2 |
| Q16 | Service socket: LF‑only HTTP headers, no `Content-Length`; command detection scans headers too; all in‑command errors become 401200. | 5.2 |
| Q17 | Initial WebSocket inactivity timer only fires if no connection was opened at all. | 5.1.1 |
| Q18 | App exits as soon as the *first* WebSocket connection closes. | 5.1.2 |
| Q19 | Parameter errors in server mode are not uploaded (page times out). Envelope errors are uploaded only for `save`, and then as raw exception text. | 4, 5.3, 7.2 |
| Q20 | Batch result uses **standard** Base64 and order `result\|cert`; sign uses URL‑safe and `cert\|sig`. | 7.1 |
| Q21 | `extra` JSON is hand‑built without escaping. `load` result names not escaped. | 7.1 |
| Q22 | AES requires `legacydes` (i.e. `cipher` without `key` fails). Unknown `algo` silently disables encryption. | 8.1, 8.3 |
| Q23 | Same AES IV reused for every field/message. | 8.3 |
| Q24 | `save` with `exts` builds descriptions like `Docs (*.pdf*.xml)` (no separator). | 3.8 |
| Q25 | Service socket state (fragments, parts) is process‑global, reset only by `echo=-`. | 5.2.3 |
| Q26 | `UrlHttpManager` read timeout is process‑global and sticky; XAdES postsign uses `servicetimeout` extra param as *connect* timeout. | 12.6, 10.3 |
| Q27 | Error dialogs are shown in addition to (not instead of) returned error strings; only for parameter/unexpected errors. | 7.2 |
| Q28 | Visible‑signature "cancelled" flag is a static that is never reset within a process (after one cancel, later PAdES operations in the same WebSocket session may be treated as cancelled). | 2.4 |
| Q29 | `mcv` with non‑numeric parts throws (generic op error) instead of a clean validation error. | 11.4 |
| Q30 | Async WebSocket: a worker that dies with an uncaught exception leaves the page waiting forever. | 5.1.3 |

Ambiguities (code does not settle):

| # | Item |
|---|---|
| A1 | TLS protocol versions offered by the Java servers (context named `TLSv1`; JDK defaults decide). |
| A2 | Platform default charset used in several `new String(bytes)`/`getBytes()` calls (DES key, cipher JSON, Storage file contents, TriphaseData bytes); assume UTF‑8. |
| A3 | `websockets.optimizedForVdi` system property has no reader in this code base. |
| A4 | Properties serialisation order (`Properties.store`) and JSON key order (org.json) are unspecified; servers parse by name. |
| A5 | Behaviour of the JS sign callback when the app returns a result without `\|` (JS decodes it as text). Never produced by the app. |

AutoScript (JS) bugs that the app must tolerate (from the page side): wrong `appname` logic; `dlgload` never sent in
server mode; `extension`/`description` keys for save in server mode; WebSocket mode URL‑safe‑encodes `dat` URLs;
`servicetimeout` ReferenceError in service mode; XML batch ReferenceError in server mode; `coSign` ignores its
data argument; envelope values not escaped; first server‑mode upload always DES; session id alphabet lacks `v`.

---

## 14. Parity checklist

| # | Feature | Java class(es) | Notes / acceptance |
|---|---|---|---|
| 1 | `afirma://` dispatch, op prefixes with optional `/` | `ProtocolInvocationLauncher` | §3.0; unknown → 600002 |
| 2 | Query parsing (`URLDecoder` semantics) | `ProtocolInvocationLauncher.extractParams`, `ProtocolInvocationUriParser.parserUri` | §2.1 |
| 3 | Java Base64 encode/decode/isBase64 | `es.gob.afirma.core.misc.Base64` | §2.2; padded URL‑safe output |
| 4 | `dat` resolution incl. gzip, http(s)/ftp download | `DataDownloader` | §2.3 |
| 5 | Java `.properties` parsing/serialisation | `AOUtil.base642Properties`, `Properties` | §2.4 |
| 6 | Keystore param `ksb64`/`keystore` + name resolution | `UrlParameters.getKeyStoreName/getDefaultKeyStoreLib`, `SimpleKeyStoreManager.getKeyStore` | §2.5 |
| 7 | Servlet URL validation | `UrlParameters.validateURL` | §2.6 |
| 8 | Id validation (≤20 alnum) | `UrlParametersTo*` | §2.7 |
| 9 | Common params (`cipher`, `key`, `aw`, `mcv`, `servicetimeout`, `dat`, `fileid`, `rtservlet`, `gzip`) | `UrlParameters.setCommonParameters` | §3.1 order & codes |
| 10 | sign/cosign/countersign params & processing | `UrlParametersToSign`, `ProtocolInvocationLauncherSign` | §3.4 |
| 11 | signandsave | `UrlParametersToSignAndSave`, `ProtocolInvocationLauncherSignAndSave` | §3.5 |
| 12 | selectcert | `UrlParametersToSelectCert`, `ProtocolInvocationLauncherSelectCert` | §3.6 |
| 13 | batch params & dispatch | `UrlParametersForBatch`, `ProtocolInvocationLauncherBatch` | §3.7, §9 |
| 14 | save | `UrlParametersToSave`, `ProtocolInvocationLauncherSave` | §3.8 |
| 15 | load | `UrlParametersToLoad`, `ProtocolInvocationLauncherLoad` | §3.9 |
| 16 | `fileid` envelope download/decrypt/parse (XML) | `ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet`, `ProtocolInvocationUriParserUtil.parseXml` | §4 |
| 17 | JSON envelope (optional) | `TriphaseDataParser.parseParamsListJson` | §4.2 |
| 18 | WebSocket server: ports, TLS, bind, retries on BindException | `AfirmaWebSocketServerManager`, `SecureSocketUtils` | §5.0, §5.1.1 |
| 19 | WebSocket V4: localhost check, idsession, echo, sync/async, `#wait`/`getresult` | `AfirmaWebSocketServerV4Sup`, `WebSocketServerOperationHandler`, `ActiveWebSocketOperationThread` | §5.1.3 |
| 20 | WebSocket lifetime: 30 s initial timer, exit on first client close, keep‑alive 60/240 s | `AfirmaWebSocketServer` | §5.1.1–5.1.2 |
| 21 | Legacy v3 WebSocket | `AfirmaWebSocketServer` | §5.1.4 (Q14) |
| 22 | Service socket: TLS suites, 90 s timer, raw HTTP framing, commands, 1 MB parts, MEMORY_ERROR | `ServiceInvocationManager`, `CommandProcessorThread` | §5.2 (Q15, Q16) |
| 23 | Direct launch: active waiting, result upload, exit | `ProtocolInvocationLauncher`, `ActiveWaitingThread`, `IntermediateServerUtil` | §5.3, §6.4 |
| 24 | Storage/Retriever client requests and error detection | `IntermediateServerUtil`, `HttpManager`, `UrlHttpManagerImpl` | §6, §12.6 |
| 25 | (Server) Storage/Retriever behaviour | `StorageService`, `RetrieveService`, `*Config`, `ErrorManager` | §6.1–6.3 (only if re‑implemented) |
| 26 | Result formats (`\|`, B64U/B64S, extra filename JSON) | `NativeSignDataProcessor`, `ProtocolInvocationLauncherBatch`, `…SelectCert`, `…Load`, `…Save` | §7.1 |
| 27 | Error strings v4.1 vs legacy, SAF mapping, localization, dialogs | `ProtocolInvocationLauncherErrorManager`, `ProtocolMessages` | §7.2, App. A/B |
| 28 | Cipher config building (`legacydes` append) | `UrlParameters` | §8.1 |
| 29 | DES cipher | `DesServerCipher` | §8.2 + worked examples |
| 30 | AES cipher with DES fallback | `AesServerCipher`, `ServerCipherFactory` | §8.3 + worked example |
| 31 | Protocol versions, upgrade to 4.1, compatibility | `ProtocolVersion`, `ProtocolInvocationLauncher.reviewProtocolVersion/isCompatibleWith` | §11 |
| 32 | `mcv` comparison vs `1.10` | `protocol.Version`, `Updater.getCurrentVersionText` | §11.4 |
| 33 | Sticky signatory | `ProtocolInvocationLauncher.stickyKeyEntry` | §12.2 |
| 34 | Keystore precedence, last selected store | `ProtocolInvocationLauncher*`, `KeyStorePreferencesManager` | §12.3 |
| 35 | Cert filters / headless / mandatoryCertSelection | `CertFilterManager` | §2.4 (semantics in keystore spec) |
| 36 | Triphase client CAdES/ASiC | `AOCAdESTriPhaseSigner`, `PreSigner`, `PostSigner`, `AOCAdESASiCSTriPhaseSigner` | §10 |
| 37 | Triphase client XAdES/ASiC/FacturaE | `AOXAdESTriPhaseSigner`, `AOXAdESASiCSTriPhaseSigner`, `AOFacturaETriPhaseSigner` | §10 |
| 38 | Triphase client PAdES | `AOPDFTriPhaseSigner`, `PDFTriPhaseSignerUtil` | §10 (`format=pades`) |
| 39 | Triphase client NONE | `AOPkcs1TriPhaseSigner` | §10 |
| 40 | TriphaseData XML (de)serialisation | `TriphaseData` | §10.2 |
| 41 | PKCS#1 over PRE, PK1, NEED_PRE | `TriphaseDataSigner`, `AOPkcs1Signer` | §10.4 |
| 42 | Server error parsing, ERR‑21 confirmations and retry | `AO*TriPhaseSigner.buildInternalException`, `AOTriphaseException`, `ProtocolInvocationLauncherUtil.getInternalException` | §10.5 |
| 43 | JSON batch client (presign/postsign, results rewrite) | `BatchSigner.signJSON`, `JSONPreSignBatchParser`, `JSONBatchInfo(Parser)`, `TriphaseDataParser` | §9.2 |
| 44 | XML batch client | `BatchSigner.signXML` | §9.3 |
| 45 | Local batch | `JSONBatchManager`, `LocalBatchSigner` | §9.4 |
| 46 | HTTP client semantics (POST body from query, headers, cookies, proxy, TLS trust, import dialog) | `UrlHttpManagerImpl`, `SSLErrorProcessor`, `SSLContextConfigurationTask` | §12.6 |
| 47 | Localhost TLS key store discovery (`autofirma.pfx`/`654321`) | `SecureSocketUtils`, `DesktopUtil` | §5.0 |
| 48 | OS launch integration (registry, .desktop, macOS launcher) | installer, `afirma-simple-installer/macos/Lanzador` | §12.1 |
| 49 | Progress dialog suppression (`dlgload`, `headless`) | `ProgressInfoDialogManager` | §12.5 |
| 50 | JS‑only APIs (setLocale, getCurrentLog, echo, checkTime) need no app support | `autoscript.js` | §12.4 |

---

## Appendix A — AutoFirma error codes (`AF` + 6 digits)

All codes that can reach the page in `err-NN:=AF<code> - <description>` strings (protocol ≥ 4.1). The description
column is the exact Java text used on the wire (Spanish, without accents unless shown). Codes are grouped by first
digit: 1 hardware, 2 internal, 3 third party, 4 communication, 5 functional, 6 request (62xxxx = request from
browser). Duplicate numbers (two names, one code) behave as the same code (`equals` compares only the number).
Codes from server‑only modules (`TriphaseErrorCode`, `TriServiceErrorCode`, `BatchServiceErrorCode`), the
configurator and the plugin manager never reach the page and are omitted.

| Code | Class | Constant | Description (Java, Spanish) |
|---|---|---|---|
| `102025` | KeyStoreErrorCode.Hardware | SMARTCARD_LOCKED | La tarjeta inteligente esta bloqueada |
| `200002` | ErrorCode.Internal | LIBRARY_NOT_FOUND | No se encuentran dependencias necesarias para la ejecucion de la operacion |
| `200003` | ErrorCode.Internal | LOADING_DATA_ERROR | Error durante la carga de datos |
| `200004` | SimpleErrorCode.Internal | CANT_LOAD_HELP | No se ha podido cargar correctamente la ayuda |
| `200005` | SimpleErrorCode.Internal | NOT_VALID_PLUGIN | Plugin no valido |
| `200006` | ErrorCode.Internal | ERROR_IMPORT_LANGUAGE | Error al importar idioma |
| `200100` | SimpleErrorCode.Internal | ENCRIPTING_SIGNATURE | Error al cifrar la firma para enviarla al servidor intermedio |
| `200101` | SimpleErrorCode.Internal | ENCRIPTING_SIGNING_CERT | Error al cifrar el certificado de firma para enviarlo al servidor intermedio |
| `200102` | ErrorCode.Internal | LOADING_LOCAL_FILE_ERROR | ⎵Error al cargar el fichero local para realizar la firma |
| `200108` | ErrorCode.Internal | SIGNING_KEY_AUTHENTICATION_ERROR | No se pudo acceder a la clave de firma |
| `200110` | ErrorCode.Internal | INVALID_SIGNING_KEY | La clave de firma no es valida o no es compatible con el algoritmo seleccionado |
| `200111` | ErrorCode.Internal | SIGNING_PKCS1_ERROR | Error al generar la firma PKCS#1 |
| `200112` | ErrorCode.Internal | INVALID_PKCS1_VALUE | La firma no se ha generado con el certificado seleccionado |
| `200113` | ErrorCode.Internal | VERIFING_PKCS1_ERROR | No se pudo verificar la firma generada |
| `200114` | ErrorCode.Internal | ENCODING_SIGNING_CERTIFICATE | Error codificando el certificado de firma |
| `200115` | ErrorCode.Internal | UNKNOWN_SIGNING_ERROR | Error desconocido durante la operacion de firma |
| `200116` | SimpleErrorCode.Internal | ENCRIPTING_SIGNATURE_EXTRA_DATA | Error al cifrar la informacion extra de firma para enviarla al servidor intermedio |
| `200117` | SimpleErrorCode.Internal | POSTPROCESING_SIGNATURE | Error en el postproceso de la firma |
| `200118` | ErrorCode.Internal | UNSUPPORTED_HASH_ALGORITHM | No se soporta un algoritmo de hash establecido internamente |
| `200118` | SimpleErrorCode.Internal | UNKNOWN_SIGNING_BY_SOCKETS_ERROR | Error desconocido durante la operacion de firma usando la comunicacion por sockets |
| `200119` | SimpleErrorCode.Internal | LOAD_FILE_TO_VIEW | Error al cargar el fichero local para visualizar la firma |
| `200200` | SimpleErrorCode.Internal | ENCRIPTING_SELECTED_CERT | Error al cifrar el certificado seleccionado para enviarlo al servidor intermedio |
| `200201` | SimpleErrorCode.Internal | UNKNOWN_SELECTING_CERT_ERROR | Error desconocido durante la operacion de seleccion de certificado |
| `200301` | SimpleErrorCode.Internal | CANT_SAVE_FILE | No se ha podido guardar el fichero en disco |
| `200305` | SimpleErrorCode.Internal | UNKNOWN_SAVING_DATA_ERROR | Error general durante la operacion de guardado de datos |
| `200400` | SimpleErrorCode.Internal | ENCRIPTING_BATCH_RESULT | Error al cifrar la informacion de las firmas del lote para enviarla al servidor intermedio |
| `200401` | SimpleErrorCode.Internal | ENCRIPTING_BATCH_SIGNING_CERT | Error al cifrar el certificado de firma para enviarlo al servidor intermedio |
| `200410` | SimpleErrorCode.Internal | INTERNAL_JSON_BATCH_ERROR | Error interno al procesar un lote de firmas JSON |
| `200411` | SimpleErrorCode.Internal | INTERNAL_XML_BATCH_ERROR | Error interno al procesar un lote de firmas XML |
| `200412` | SimpleErrorCode.Internal | INTERNAL_LOCAL_BATCH_ERROR | Error interno realizando la firma batch local |
| `200413` | SimpleErrorCode.Internal | UNKNOWN_BATCH_ERROR | Error desconocido al procesar un lote de firmas |
| `200600` | SimpleErrorCode.Internal | UNKNOWN_LOADING_DATA_ERROR | Error general durante la operacion de carga de fichero |
| `200601` | SimpleErrorCode.Internal | CANT_LOAD_FILE | Error al cargar el fichero local |
| `200701` | SimpleErrorCode.Internal | NEEDS_UPDATED_VERSION | Se necesita actualizar la aplicacion |
| `200702` | SimpleErrorCode.Internal | NO_DETECTED_PROXIES | No se han detectado proxies en el sisema |
| `200800` | SimpleErrorCode.Internal | ERROR_LOAD_TRUSTED_CERT | Error al cargar el certificado de confianza |
| `200801` | SimpleErrorCode.Internal | TRUSTSTORE_INCORRECT_INSTALLATION | El almacen de confianza de Autofirma no se encuentra instalado correctamente |
| `201101` | KeyStoreErrorCode.Internal | LOADING_KEYSTORE_INTERNAL_ERROR | Error generico al cargar el almacen de certificados |
| `201103` | KeyStoreErrorCode.Internal | LOADING_PRIVATE_KEY_ERROR | Error al cargar la clave del certificado |
| `201106` | KeyStoreErrorCode.Internal | LOADING_CERTIFICATE_ERROR | Error al cargar el certificado suelto o en PKCS#7 |
| `201107` | KeyStoreErrorCode.Internal | LOADING_WINDOWS_KEYSTORE_ERROR | Error al cargar el almacen de certificados de Windows |
| `201108` | KeyStoreErrorCode.Internal | LOADING_MOZILLA_KEYSTORE_ERROR | Error al cargar el almacen de certificados de Mozilla |
| `201109` | KeyStoreErrorCode.Internal | LOADING_APPLE_KEYSTORE_ERROR | Error al cargar el almacen de certificados Apple KeyRing |
| `201110` | KeyStoreErrorCode.Internal | LOADING_PKCS12_KEYSTORE_ERROR | Error al cargar el almacen de certificados PKCS#12 |
| `201111` | KeyStoreErrorCode.Internal | LOADING_JAVA_KEYSTORE_ERROR | Error al cargar el almacen de certificados JKS |
| `201112` | KeyStoreErrorCode.Internal | LOADING_PUBLIC_WINDOWS_KEYSTORE_ERROR | Error al cargar el almacen de certificados de claves publicas de Windows |
| `201113` | KeyStoreErrorCode.Internal | LOADING_PKCS11_KEYSTORE_ERROR | Error al cargar el almacen de certificados a traves del PKCS#11 |
| `201114` | KeyStoreErrorCode.Internal | LOADING_JMULTICARD_KEYSTORE_ERROR | Error al cargar el almacen de certificados con JMulticard |
| `201115` | KeyStoreErrorCode.Internal | LOADING_FILE_CERTSTORE_ERROR | Error al cargar un certificado desde fichero |
| `201116` | KeyStoreErrorCode.Internal | UNDEFINED_DEFAULT_KEYSTORE | No hay definido un almacen de claves por defecto para este sistema operativo |
| `211001` | BinaryErrorCode.Internal | UNKWNON_BINARY_SIGNING_ERROR | Error desconocido en la generacion de la firma binaria |
| `211002` | BinaryErrorCode.Internal | INTERNAL_BINARY_SIGNING_ERROR | Error interno en la generacion de la firma binaria |
| `211003` | BinaryErrorCode.Internal | GENERATING_TIMESTAMP_ERROR | Error generando sello de tiempo binario |
| `212001` | PdfErrorCode.Internal | UNKWNON_PADES_SIGNING_ERROR | Error desconocido en la generacion de la firma PAdES |
| `212002` | PdfErrorCode.Internal | INTERNAL_PADES_SIGNING_ERROR | Error interno en la generacion de la firma PAdES |
| `212003` | PdfErrorCode.Internal | SIGNING_PDF_WITH_UNREGISTER_SIGNATURES | Se esta intentando firmar una firma PDF con firmas sin registrar |
| `212004` | PdfErrorCode.Internal | SIGNING_PDF_WITH_BAD_PASSWORD | La contrasena del PDF no era correcta |
| `212005` | PdfErrorCode.Internal | SIGNING_PDF_WITHOUT_PASSWORD | El PDF necesita contrasena |
| `212006` | PdfErrorCode.Internal | SIGNING_PDF_WITH_MODIFIED_FORM | Se esta intentando firmar un PDF con un formulario modificado despues de una firma anterior |
| `212007` | PdfErrorCode.Internal | SIGNING_PDF_WITH_CERTIFIED_SIGN | Se esta intentando firmar un PDF certificado que no admite nuevas firmas |
| `212008` | PdfErrorCode.Internal | SIGNING_PDF_WITH_SUSPICION_OF_PSA | Se esta intentando firmar un PDF sospechoso de haber sido modificado tras la firma |
| `213001` | XMLErrorCode.Internal | UNKWNON_XML_SIGNING_ERROR | Error desconocido en la generacion de la firma XML |
| `213002` | XMLErrorCode.Internal | INTERNAL_XML_SIGNING_ERROR | Error interno en la generacion de la firma XML |
| `213003` | ODFErrorCode.Internal | UNKWNON_ODF_SIGNING_ERROR | Error desconocido en la generacion de la firma ODF |
| `213004` | ODFErrorCode.Internal | INTERNAL_ODF_SIGNING_ERROR | Error interno en la generacion de la firma ODF |
| `213004` | XMLErrorCode.Internal | UNSUPPORTED_TRANSFORMATION_ALGORITHM | El tipo de transformacion declarado no esta soportado |
| `213005` | OOXMLErrorCode.Internal | UNKWNON_OOXML_SIGNING_ERROR | Error desconocido en la generacion de la firma OOXML |
| `213006` | OOXMLErrorCode.Internal | INTERNAL_OOXML_SIGNING_ERROR | Error interno en la generacion de la firma OOXML |
| `214001` | ErrorCode.Internal | BUILDING_ASIC_CONTAINER_ERROR | Error al construir el contenedor ASiC de la nueva firma |
| `220001` | SimpleErrorCode.Internal | SOCKET_INITIALIZING_ERROR | No se pudo abrir el socket de comunicacion |
| `220002` | SimpleErrorCode.Internal | DECRYPTING_PARAMS_ERROR | Error desencriptando los datos del servidor |
| `220003` | SimpleErrorCode.Internal | ERROR_RECIVED_FROM_CLIENT | El servicio cliente ya notifico un error durante la peticion |
| `220004` | SimpleErrorCode.Internal | ENCRYPTING_PARAMS_ERROR | Error encriptando los datos del servidor |
| `220008` | SimpleErrorCode.Internal | LOADING_SSL_KEYSTORE_ERROR | No se ha podido cargar el almacen de claves SSL |
| `230100` | SimpleErrorCode.Internal | GENERIC_LANGUAGE_IMPORT_ERROR | Error importando el idioma |
| `230101` | SimpleErrorCode.Internal | CANT_READ_FILE | No se ha podido leer correctamente el archivo ZIP |
| `230102` | SimpleErrorCode.Internal | CANT_CREATE_DIRECTORY | Se ha producido un error al crear el directorio del idioma |
| `300001` | BinaryErrorCode.ThirdParty | BOUNCYCASTLE_VERSION_NOT_SUPPORTED | Se ha encontrado una version de Spongycastle no soportada |
| `300002` | PdfErrorCode.ThirdParty | ITEXT_VERSION_NOT_SUPPORTED | Se ha encontrado una version de iText no soportada |
| `300003` | KeyStoreErrorCode.ThirdParty | SUN_MSCAPI_PROVIDER_NOT_FOUND | No se ha encontrado el proveedor MSCAPI de Sun |
| `300004` | KeyStoreErrorCode.ThirdParty | AFIRMA_MSCAPI_ADDRESBOOK_PROVIDER_NOT_FOUND | No se ha encontrado el proveedor MSCAPI del Cliente @firma |
| `300005` | KeyStoreErrorCode.ThirdParty | AFIRMA_SINGLE_CERT_PROVIDER_NOT_FOUND | No se ha encontrado el proveedor SingleCert del Cliente @firma |
| `300202` | ErrorCode.ThirdParty | INVALID_OPERATION_XML | ⎵La respuesta del servidor intermedio al descargar la informacion no es un XML valido |
| `300400` | ErrorCode.ThirdParty | PRESIGN_HTTP_ERROR | El servicio de prefirma devolvio un error HTTP |
| `300401` | ErrorCode.ThirdParty | MALFORMED_PRESIGN_RESPONSE | La respuesta del servidor trifasico al hacer la prefirma no es valida |
| `300402` | ErrorCode.ThirdParty | PRESIGNS_NOT_FOUND | No se han obtenido prefirmas del servicio de prefirma |
| `300404` | ErrorCode.ThirdParty | POSTSIGN_HTTP_ERROR | El servicio de postfirma devolvio un error HTTP |
| `300405` | ErrorCode.ThirdParty | POSTSIGN_ERROR | La respuesta del servidor trifasico al hacer la postfirma no es valida |
| `300407` | ErrorCode.ThirdParty | MALFORMED_POSTSIGN_RESPONSE | El servidor trifasico devolvio una respuesta con texto OK pero no llega el formato correcto |
| `300409` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_1 | ERR-1 en la prefirma: No se ha indicado la operacion a realizar |
| `300410` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_2 | ERR-2 en la prefirma: No se ha indicado el identificador del documento |
| `300411` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_3 | ERR-3 en la prefirma: No se ha indicado el algoritmo de firma |
| `300412` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_4 | ERR-4 en la prefirma: No se ha indicado el formato de firma |
| `300413` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_5 | ERR-5 en la prefirma: No se ha indicado el certificado de usuario |
| `300414` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_6 | ERR-6 en la prefirma: El formato de los parametros adicionales suministrados es erroneo |
| `300415` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_7 | ERR-7 en la prefirma: El certificado de usuario no esta en formato X.509 |
| `300416` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_8 | ERR-8 en la prefirma: Formato de firma no soportado |
| `300417` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_9 | ERR-9 en la prefirma: Error realizando la prefirma |
| `300418` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_10 | ERR-10 en la prefirma: Error al almacenar el documento |
| `300419` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_11 | ERR-11 en la prefirma: Operacion desconocida |
| `300420` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_12 | ERR-12 en la prefirma: Error realizando la postfirma |
| `300421` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_13 | ERR-13 en la prefirma: No se indicado una sub-operacion valida a realizar (firma, cofirma,...) |
| `300422` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_14 | ERR-14 en la prefirma: Error al recuperar el documento |
| `300423` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_15 | ERR-15 en la prefirma: El formato de los datos de sesion suministrados es erroneo |
| `300424` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_16 | ERR-16 en la prefirma: Error al generar el codigo de verificacion de las firmas |
| `300425` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_17 | ERR-17 en la prefirma: Error al comprobar el codigo de verificacion de las firmas |
| `300426` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_18 | ERR-18 en la prefirma: Error de integridad en la firma |
| `300427` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_19 | ERR-19 en la prefirma: El formato de los datos de operacion suministrados es erroneo |
| `300428` | ErrorCode.ThirdParty | TRI_SERVER_PRESIGN_ERROR_20 | ERR-20 en la prefirma: Algoritmo de firma no soportado |
| `300430` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_1 | ERR-1 en la postfirma: No se ha indicado la operacion a realizar |
| `300431` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_2 | ERR-2 en la postfirma: No se ha indicado el identificador del documento |
| `300432` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_3 | ERR-3 en la postfirma: No se ha indicado el algoritmo de firma |
| `300433` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_4 | ERR-4 en la postfirma: No se ha indicado el formato de firma |
| `300434` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_5 | ERR-5 en la postfirma: No se ha indicado el certificado de usuario |
| `300435` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_6 | ERR-6 en la postfirma: El formato de los parametros adicionales suministrados es erroneo |
| `300436` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_7 | ERR-7 en la postfirma: El certificado de usuario no esta en formato X.509 |
| `300437` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_8 | ERR-8 en la postfirma: Formato de firma no soportado |
| `300438` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_9 | ERR-9 en la postfirma: Error realizando la prefirma |
| `300439` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_10 | ERR-10 en la postfirma: Error al almacenar el documento |
| `300440` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_11 | ERR-11 en la postfirma: Operacion desconocida |
| `300441` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_12 | ERR-12 en la postfirma: Error realizando la postfirma |
| `300442` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_13 | ERR-13 en la postfirma: No se indicado una sub-operacion valida a realizar (firma, cofirma,...) |
| `300443` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_14 | ERR-14 en la postfirma: Error al recuperar el documento |
| `300444` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_15 | ERR-15 en la postfirma: El formato de los datos de sesion suministrados es erroneo |
| `300445` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_16 | ERR-16 en la postfirma: Error al generar el codigo de verificacion de las firmas |
| `300446` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_17 | ERR-17 en la postfirma: Error al comprobar el codigo de verificacion de las firmas |
| `300447` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_18 | ERR-18 en la postfirma: Error de integridad en la firma |
| `300448` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_19 | ERR-19 en la postfirma: El formato de los datos de operacion suministrados es erroneo |
| `300449` | ErrorCode.ThirdParty | TRI_SERVER_POSTSIGN_ERROR_20 | ERR-20 en la postfirma: Algoritmo de firma no soportado |
| `300451` | ErrorCode.ThirdParty | TRI_SERVER_UNKNOWN_PRESIGN_ERROR | No se reconoce el error remitido por el servicio de prefirma |
| `300452` | ErrorCode.ThirdParty | TRI_SERVER_UNKNOWN_POSTSIGN_ERROR | No se reconoce el error remitido por el servicio de postfirma |
| `300601` | BatchErrorCode.ThirdParty | JSON_BATCH_PRESIGN_ERROR | El servicio de prefirma de lotes JSON devolvio un error |
| `300602` | BatchErrorCode.ThirdParty | JSON_BATCH_POSTSIGN_ERROR | El servicio de postfirma de lotes JSON devolvio un error |
| `300701` | BatchErrorCode.ThirdParty | XML_BATCH_PRESIGN_ERROR | El servicio de prefirma de lotes XML devolvio un error |
| `300702` | BatchErrorCode.ThirdParty | XML_BATCH_POSTSIGN_ERROR | El servicio de postfirma de lotes XML devolvio un error |
| `400002` | SimpleErrorCode.Communication | PROXY_CONNECTION | Conexion incorrecta con proxy |
| `400004` | ErrorCode.Communication | INVALID_DOMAIN_SSL_CERTIFICATE_ERROR | El certificado SSL no esta expedido para el dominio al que pertenece el servidor |
| `401100` | SimpleErrorCode.Communication | RECIVING_DATA_OF_SIGN_OPERATION | Error en la descarga de la operacion de firma |
| `401101` | SimpleErrorCode.Communication | RECIVING_DATA_OF_CERT_OPERATION | Error en la descarga de la operacion de seleccion de certificado |
| `401102` | SimpleErrorCode.Communication | RECIVING_DATA_OF_BATCH_OPERATION | Error en la descarga de la operacion de lote |
| `401103` | SimpleErrorCode.Communication | RECIVING_DATA_OF_SAVE_OPERATION | Error en la descarga de la operacion de guardado de datos |
| `401104` | SimpleErrorCode.Communication | RECIVING_DATA_OF_LOAD_OPERATION | Error en la descarga de la operacion de carga de datos |
| `401105` | SimpleErrorCode.Communication | RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION | Error en la descarga de la operacion de firma y guardado |
| `401106` | SimpleErrorCode.Communication | RECIVING_DATA_OF_SIGN_TIMEOUT | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma |
| `401107` | SimpleErrorCode.Communication | RECIVING_DATA_OF_CERT_TIMEOUT | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de seleccion de certificados |
| `401108` | SimpleErrorCode.Communication | RECIVING_DATA_OF_BATCH_TIMEOUT | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma de lote |
| `401109` | SimpleErrorCode.Communication | RECIVING_DATA_OF_SAVE_TIMEOUT | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de guardado |
| `401110` | SimpleErrorCode.Communication | RECIVING_DATA_OF_LOAD_TIMEOUT | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de carga de datos |
| `401111` | SimpleErrorCode.Communication | RECIVING_DATA_OF_SIGN_AND_SAVE_TIMEOUT | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma y guardado |
| `401200` | SimpleErrorCode.Communication | SENDING_RESULT_OPERATION | Error en el envio del resultado de la operacion |
| `401201` | SimpleErrorCode.Communication | SENDING_RESULT_TIMEOUT | Se excedio el tiempo maximo de espera en la llamada al servicio de guardado del servidor intermedio |
| `401300` | ErrorCode.Communication | PRESIGN_SERVICE_CONNECTION_ERROR | Error de conexion con el servidor trifasico al hacer la prefirma |
| `401301` | ErrorCode.Communication | PRESIGN_SERVICE_COMMUNICATION_ERROR | Error de comunicacion con el servidor trifasico al hacer la prefirma |
| `401302` | ErrorCode.Communication | PRESIGN_SERVICE_TIMEOUT | Se excedio el tiempo maximo de espera en la llamada a la prefirma del servidor trifasico |
| `401400` | ErrorCode.Communication | POSTSIGN_SERVICE_CONNECTION_ERROR | Error de conexion con el servidor trifasico al hacer la posfirma |
| `401401` | ErrorCode.Communication | POSTSIGN_SERVICE_COMMUNICATION_ERROR | Error de comunicacion con el servidor trifasico al hacer la posfirma |
| `401402` | ErrorCode.Communication | POSTSIGN_SERVICE_TIMEOUT | Se excedio el tiempo maximo de espera en la llamada a la postfirma del servidor trifasico |
| `401500` | BatchErrorCode.Communication | JSON_BATCH_PRESIGN_CONNECTION_ERROR | Error de conexion con el servidor trifasico al hacer la prefirma Batch JSON |
| `401501` | BatchErrorCode.Communication | JSON_BATCH_PRESIGN_COMMUNICATION_ERROR | Error de comunicacion con el servidor trifasico al hacer la prefirma Batch JSON |
| `401502` | BatchErrorCode.Communication | JSON_BATCH_PRESIGN_TIMEOUT | Se excedio el tiempo maximo de espera en la llamada a la prefirma de lote JSON del servidor trifasico |
| `401600` | BatchErrorCode.Communication | JSON_BATCH_POSTSIGN_CONNECTION_ERROR | Error de conexion con el servidor trifasico al hacer la posfirma Batch JSON |
| `401601` | BatchErrorCode.Communication | JSON_BATCH_POSTSIGN_COMMUNICATION_ERROR | Error de comunicacion con el servidor trifasico al hacer la posfirma Batch JSON |
| `401602` | BatchErrorCode.Communication | JSON_BATCH_POSTSIGN_TIMEOUT | Se excedio el tiempo maximo de espera en la llamada a la postfirma de lote JSON del servidor trifasico |
| `401700` | BatchErrorCode.Communication | XML_BATCH_PRESIGN_CONNECTION_ERROR | Error de conexion con el servidor trifasico al hacer la prefirma Batch XML |
| `401701` | BatchErrorCode.Communication | XML_BATCH_PRESIGN_COMMUNICATION_ERROR | Error de comunicacion con el servidor trifasico al hacer la prefirma Batch XML |
| `401702` | BatchErrorCode.Communication | XML_BATCH_PRESIGN_TIMEOUT | Se excedio el tiempo maximo de espera en la llamada a la prefirma de lote XML del servidor trifasico |
| `401800` | BatchErrorCode.Communication | XML_BATCH_POSTSIGN_CONNECTION_ERROR | Error de conexion con el servidor trifasico al hacer la posfirma Batch XML |
| `401801` | BatchErrorCode.Communication | XML_BATCH_POSTSIGN_COMMUNICATION_ERROR | Error de comunicacion con el servidor trifasico al hacer la posfirma Batch XML |
| `401802` | BatchErrorCode.Communication | XML_BATCH_POSTSIGN_TIMEOUT | Se excedio el tiempo maximo de espera en la llamada a la postfirma de lote XML del servidor trifasico |
| `410001` | ErrorCode.Communication | TSA_CONNECTION_ERROR | Error en la comunicacion con la autoridad de sellado de tiempo |
| `411001` | XMLErrorCode.Communication | DERREFERENCING_DATA_ERROR | No se han podido cargar de una URI los datos para la firma XML |
| `420001` | SimpleErrorCode.Communication | EXTERNAL_REQUEST | Se ha realizado la peticion desde un puerto externo |
| `420501` | SimpleErrorCode.Communication | SENDING_RESULT_OPERATION_BY_SOCKET | Error en el envio del resultado de la operacion por socket |
| `420502` | SimpleErrorCode.Communication | READING_FROM_SOCKET | No se pudieron leer los datos del socket |
| `500001` | ErrorCode.Functional | CANCELLED_OPERATION | Operacion cancelada por el usuario |
| `500002` | ErrorCode.Functional | INVALID_SIGNATURE | La firma que se trata de procesar es invalida |
| `500003` | ErrorCode.Functional | INCOMPATIBLE_OPERATING_SYSTEM | Sistema operativo no compatible con la operacion |
| `500004` | OOXMLErrorCode.Functional | INCOMPATIBLE_JRE | JRE no compatible con la operacion |
| `500005` | SimpleErrorCode.Functional | MINIMUM_VERSION_NON_SATISTIED | La web solicito una version posterior de Autofirma |
| `500006` | SimpleErrorCode.Functional | SIGNER_REQUIREMENT_NOT_SUPPORTED | El firmador hizo una peticion de datos no soportada |
| `500007` | SimpleErrorCode.Functional | VALIDATOR_REQUIREMENT_NOT_SUPPORTED | El validador hizo una peticion de datos no soportada |
| `501001` | ErrorCode.Functional | CERTIFICATE_NEEDED | Error en la operacion, no hay certificados |
| `501001` | SimpleErrorCode.Functional | NO_CERTS_FOUND_SIGNING | No se han encontrado certificados para realizar la seleccion |
| `501002` | ErrorCode.Functional | INVALID_FORMAT_FILE | El formato de fichero no es valido para la operacion que se intenta realizar |
| `501003` | ErrorCode.Functional | INVALID_SMARTCARD_PIN | El PIN del la tarjeta inteligente es incorrecto |
| `501005` | ErrorCode.Functional | DOCUMENT_TOO_LARGE | El documento supera el tamano maximo permitido |
| `501006` | ErrorCode.Functional | COMPATIBLE_SIGNATURE_NOT_FOUND | La firma no es compatible con el formato de firma utilizado |
| `501007` | ErrorCode.Functional | SIGNING_LTS | Se esta intentando firmar una firma longeva que quedara invalidada |
| `501008` | ErrorCode.Functional | SIGNING_WITH_POLICY_INCOMPATIBILITY | La firma resultante sera incompatible con la politica de firma |
| `501009` | SimpleErrorCode.Functional | CANT_IDENTIFY_SIGNATURE_FORMAT | No se ha podido identificar un formato de firma para los datos |
| `501010` | SimpleErrorCode.Functional | VISIBLE_SIGNATURE_IS_MANDATORY | La operacion marco como obligatoria la firma visible PDF |
| `501011` | XMLErrorCode.Functional | XPATH_NOT_FOUND | Una o varias firmas incluidas en el documento no contienen un algoritmo XPath |
| `502001` | SimpleErrorCode.Functional | NO_CERTS_FOUND_SELECTING_CERT | No se han encontrado certificados para realizar la seleccion |
| `504001` | SimpleErrorCode.Functional | NO_CERTS_FOUND_SIGNING_BATCH | No se han encontrado certificados para realizar la firma del lote |
| `506001` | MassiveErrorCode.Functional | INDIR_NOT_FOUND | El directorio de entrada no existe |
| `506002` | MassiveErrorCode.Functional | ACCESS_TO_DIR_IS_NOT_ALLOWED | No se tiene acceso al directorio indicado |
| `507001` | ValidationErrorCode.Functional | INCOMPATIBLE_SIGNATURE | El documento no esta firmado o la firma no es compatible |
| `510001` | BinaryErrorCode.Functional | SIGNATURE_DOESNT_CONTAIN_DATA | La firma no contiene los datos firmados necesarios para la operacion |
| `510002` | XMLErrorCode.Functional | XML_DOCUMENT_NEEDED | La firma requiere que los datos sean un documento XML |
| `510003` | ODFErrorCode.Functional | ODF_DOCUMENT_NEEDED | La firma requiere que los datos sean un documento ODF |
| `510004` | OOXMLErrorCode.Functional | OOXML_DOCUMENT_NEEDED | La firma requiere que los datos sean un documento OOXML |
| `510005` | PdfErrorCode.Functional | PDF_DOCUMENT_NEEDED | La firma requiere que los datos sean un documento PDF |
| `510006` | ErrorCode.Functional | SIGNING_MALFORMED_SIGNATURE | La firma no es compatible o esta mal formada |
| `510007` | XMLErrorCode.Functional | TRI_SIGNING_SIGNATURE | No se permite firmar una firma XML en el modo de firma trifasica |
| `510008` | XAdESErrorCode.Functional | FACTURAE_ALREADY_SIGNED | La factura ya tiene una firma electronica y no admite firmas adicionales |
| `510009` | XAdESErrorCode.Functional | FACTURAE_NEEDED | La firma requiere que los datos sean FacturaE |
| `511003` | ErrorCode.Functional | KEYSTORE_LOCKED | El almacen de claves esta bloqueado |
| `511004` | ErrorCode.Functional | SMARTCARD_LOCKED | La tarjeta inteligente esta bloqueada |
| `521000` | SimpleErrorCode.Functional | POLICY_DEFAULT_ERROR | Ha ocurrido un error configurando la politica |
| `521001` | SimpleErrorCode.Functional | INVALID_POLICY_IDENTIFIER | El identificador de politica no puede ser nulo ni vacio |
| `521002` | SimpleErrorCode.Functional | INVALID_POLICY_IDENTIFIER_URI | El identificador debe ser una URI valida |
| `521003` | SimpleErrorCode.Functional | MISSING_DIGEST_ALGORITHM | Si se indica la huella digital es obligatorio indicar tambien el algoritmo |
| `521004` | SimpleErrorCode.Functional | UNREACHABLE_POLICY_IDENTIFIER_URI | Si no se especifica la huella digital, el identificador debe ser una URI accesible |
| `521005` | SimpleErrorCode.Functional | INVALID_POLICY_IDENTIFIER_HASH_BASE64 | La huella digital debe estar en formato Base64 |
| `521006` | SimpleErrorCode.Functional | INVALID_POLICY_QUALIFIER_URI | El calificador debe ser una URI valida |
| `521007` | SimpleErrorCode.Functional | INVALID_POLICY_IDENTIFIER_OID | El identificador debe tener un formato OID valido |
| `521008` | SimpleErrorCode.Functional | EMPTY_POLICY_HASH | La huella digital no puede ser nula ni vacia |
| `521009` | SimpleErrorCode.Functional | INVALID_POLICY_QUALIFIER_URL | El calificador debe ser una URL valida |
| `521010` | SimpleErrorCode.Functional | INVALID_PROXY_CONFIG | La configuracion de proxy no es valida |
| `530007` | SimpleErrorCode.Functional | INVALID_PLUGIN_FILE | El plugin no es valido para ser importado |
| `530009` | SimpleErrorCode.Functional | PLUGIN_FILE_NOT_FOUND | No se ha encontrado el fichero del plugin |
| `600002` | SimpleErrorCode.Request | UNSUPPORTED_OPERATION | La operacion no esta soportada |
| `600009` | ErrorCode.Request | UNSUPPORTED_CIPHER_KEY | La clave de cifrado recibida no esta soportada |
| `600010` | ErrorCode.Request | LOCAL_RETRIEVE_URL | La URL del servlet de recuperacion no puede ser local |
| `600011` | KeyStoreErrorCode.Request | UNSUPPORTED_KEYSTORE | El almacen de claves solicitado no es compatible con el entorno de ejecucion |
| `600012` | ErrorCode.Request | INVALID_READ_TIMEOUT | El tiempo de espera de lectura de los servicios no es valido |
| `600100` | ErrorCode.Request | DATA_NOT_FOUND | No se ha recibido los datos en la peticion ni el id del fichero a descargar para la operacion de firma |
| `600101` | ErrorCode.Request | RETRIEVE_URL_TO_SIGN_NOT_FOUND | No se ha recibido la URL del servlet para descargar la informacion de la operacion de firma |
| `600102` | ErrorCode.Request | STORAGE_URL_TO_SIGN_NOT_FOUND | No se ha recibido la URL del servlet para guardar la firma en la operacion de firma |
| `600104` | ErrorCode.Request | SIGNATURE_FORMAT_NOT_FOUND | No se ha recibido el formato de firma para la operacion de firma |
| `600105` | ErrorCode.Request | UNSUPPORTED_SIGNATURE_FORMAT | El formato de firma indicado en la operacion de firma no esta soportado |
| `600106` | ErrorCode.Request | SIGNATURE_ALGORITHM_NOT_FOUND | No se ha recibido el algoritmo de firma para la operacion de firma |
| `600107` | ErrorCode.Request | UNSUPPORTED_SIGNATURE_ALGORITHM | El algoritmo de firma indicado en la operacion de firma no esta soportado |
| `600110` | ErrorCode.Request | UNSUPPORTED_COUNTERSIGN_CONFIG | No se soporta la configuracion de nodos a contrafirmar |
| `600111` | ErrorCode.Request | UNSUPPORTED_POLICY_HASH_ALGORITHM | El algoritmo de huella indicado en la politica de firma no esta soportado |
| `600112` | ErrorCode.Request | INVALID_COUNTERSIGNATURE_INDEX | El numero indicado no se corresponde con la posicion de ninguna contrafirma |
| `600113` | ErrorCode.Request | INVALID_TIMESTAMP_HASH_ALGORITHM | El algoritmo de huella para el sello de tiempo no esta soportado |
| `600116` | ErrorCode.Request | INVALID_RETRIEVE_URL_TO_SIGN | La URL del servlet de descarga para la operacion de firma esta mal formado |
| `600117` | ErrorCode.Request | RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL | La URL del servlet de descarga para la operacion de firma no puede ser local |
| `600118` | ErrorCode.Request | INVALID_STORAGE_URL_TO_SIGN | La URL del servlet de guardado para la operacion de firma esta mal formada |
| `600119` | ErrorCode.Request | LOCAL_STORAGE_URL_TO_SIGN | La URL del servlet de guardado para la operacion de firma no puede ser local |
| `600120` | ErrorCode.Request | INVALID_SESSION_ID_TO_SIGN | El id de sesion recibido para la firma no es valido |
| `600121` | SimpleErrorCode.Request | INVALID_FORMAT_SIGNATURE_PARAM | Alguna de las propiedades de firma es incorrecta |
| `600200` | ErrorCode.Request | STORAGE_URL_TO_SELECT_CERT_NOT_FOUND | No se ha recibido la URL del servlet para guardar el certificado en la operacion de enviar certificado |
| `600201` | ErrorCode.Request | INVALID_SESSION_ID_TO_SELECT_CERT | El id de sesion recibido para la seleccion de certificado no es valido |
| `600202` | ErrorCode.Request | INVALID_STORAGE_URL_TO_SELECT_CERT | La URL del servlet de guardado para la operacion de seleccion de certificado esta mal formada |
| `600203` | ErrorCode.Request | LOCAL_STORAGE_URL_TO_SELECT_CERT | La URL del servlet de guardado para la operacion de seleccion de certificado no puede ser local |
| `600300` | ErrorCode.Request | DATA_TO_SAVE_NOT_FOUND | No se ha recibido los datos en la peticion ni el id del fichero a descargar para la operacion de guardado |
| `600301` | ErrorCode.Request | RETRIEVE_URL_TO_SAVE_NOT_FOUND | No se ha recibido la URL del servlet para descargar la informacion de la operacion de guardado |
| `600302` | ErrorCode.Request | STORAGE_URL_TO_SAVE_NOT_FOUND | No se ha recibido la URL del servlet para guardar la firma en la operacion de guardado |
| `600303` | ErrorCode.Request | INVALID_SESSION_ID_TO_SAVE | El id de sesion recibido para el guardado de datos no es valido |
| `600304` | ErrorCode.Request | INVALID_STORAGE_URL_TO_SAVE | La URL del servlet de guardado para la operacion de guargado esta mal formada |
| `600305` | ErrorCode.Request | LOCAL_STORAGE_URL_TO_SAVE | La URL del servlet de guardado para la operacion de guardado no puede ser local |
| `600306` | ErrorCode.Request | FILENAME_TO_SAVE_NOT_FOUND | No se ha recibido el nombre por defecto para el fichero de datos a guardar |
| `600307` | ErrorCode.Request | FILE_EXTENSION_TO_SAVE_NOT_FOUND | No se ha recibido la extension por defecto para el fichero de datos a guardar |
| `600402` | ErrorCode.Request | STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND | No se ha recibido la URL del servlet para guardar la firma en la operacion de firma de lotes |
| `600403` | ErrorCode.Request | ID_SESSION_TO_SIGN_BATCH_NOT_FOUND | No se ha recibido el id del fichero a guardar para la operacion de firma de lotes |
| `600405` | ErrorCode.Request | PRESIGN_BATCH_URL_NOT_FOUND | No se ha recibido el URL de prefirma de la firma de lotes |
| `600406` | ErrorCode.Request | POSTSIGN_BATCH_URL_NOT_FOUND | No se ha recibido el URL de postfirma de la firma de lotes |
| `600410` | ErrorCode.Request | INVALID_SESSION_ID_TO_SIGN_BATCH | El id de sesion recibido no es valido |
| `600411` | ErrorCode.Request | INVALID_STORAGE_URL_TO_SIGN_BATCH | La URL del servlet de guardado para la operacion de firma de lotes esta mal formada |
| `600412` | ErrorCode.Request | LOCAL_STORAGE_URL_TO_SIGN_BATCH | La URL del servlet de guardado para la operacion de firma de lotes no puede ser local |
| `600413` | ErrorCode.Request | INVALID_PRESIGN_BATCH_URL | La URL de prefirma de la firma de lotes esta mal formada |
| `600414` | ErrorCode.Request | LOCAL_PRESIGN_BATCH_URL | La URL de prefirma de la firma de lotes no puede ser local |
| `600415` | ErrorCode.Request | INVALID_POSTSIGN_BATCH_URL | La URL de postfirma de la firma de lotes esta mal formada |
| `600416` | ErrorCode.Request | LOCAL_POSTSIGN_BATCH_URL | La URL de postfirma de la firma de lotes no puede ser local |
| `600417` | BatchErrorCode.Request | INVALID_PARAMS_TO_PRESIGN_JSON_BATCH | El servicio de prefirma de lote JSON informo de un error en los parametros enviados |
| `600418` | BatchErrorCode.Request | INVALID_PARAMS_TO_POSTSIGN_JSON_BATCH | El servicio de postfirma de lote JSON informo de un error en los parametros enviados |
| `600419` | BatchErrorCode.Request | MALFORMED_JSON_BATCH | El lote no es un JSON valido o esta mal formado |
| `600420` | SimpleErrorCode.Request | INVALID_FORMAT_SIGN_BATCH_PARAM | Alguna de las propiedades de firma del lote es incorrecta |
| `600501` | BatchErrorCode.Request | INVALID_PARAMS_TO_PRESIGN_XML_BATCH | El servicio de prefirma de lote XML informo de un error en los parametros enviados |
| `600502` | BatchErrorCode.Request | INVALID_PARAMS_TO_POSTSIGN_XML_BATCH | El servicio de postfirma de lote XML informo de un error en los parametros enviados |
| `600503` | BatchErrorCode.Request | MALFORMED_XML_BATCH | El lote no es un XML valido o esta mal formado |
| `600601` | MassiveErrorCode.Request | DECODING_HASH_ERROR | Se ha proporcionado un hash no valido para la firma explicita |
| `600701` | ErrorCode.Request | INVALID_PARAMS_TO_PRESIGN | El servicio de prefirma informo de un error en los parametros enviados |
| `600702` | ErrorCode.Request | INVALID_PARAMS_TO_POSTSIGN | El servicio de postfirma informo de un error en los parametros enviados |
| `610001` | XMLErrorCode.Request | INVALID_ENCODING_URI | La URI del algoritmo de codificacion no es valida |
| `610002` | XMLErrorCode.Request | INVALID_REFERENCES_HASH_ALGORITHM_URI | La URI del algoritmo de huella de las referencias no es valida |
| `610003` | XMLErrorCode.Request | INVALID_CANONICALIZATION_URI | La URI del algoritmo de canonicalizacion no es valida |
| `610004` | XMLErrorCode.Request | INVALID_PRECALCULATED_DATA_HASH_ALGORITHM | El algoritmo de huella de los datos precalculados no es valido |
| `610005` | XMLErrorCode.Request | INVALID_TRANSFORMATION | La transformacion no es valida |
| `610006` | XMLErrorCode.Request | INVALID_REFERENCE_URI | La URI a los datos firmados no es valida |
| `610007` | XMLErrorCode.Request | INVALID_NODE_SELECTOR_XPATH | La ruta XPATH para la seleccion de nodo no es valida |
| `610201` | XAdESErrorCode.Request | REFERENCE_HASH_NOT_FOUND | No se ha indicado la huella digital de una referencia a los datos firmados |
| `610202` | XAdESErrorCode.Request | INVALID_REFERENCE_HASH | Error al decodificar el hash de los datos referenciados |
| `610203` | XAdESErrorCode.Request | MANIFEST_REFERENCES_NOT_FOUND | No se han proporcionado referencias para el manifest de firma |
| `610204` | XAdESErrorCode.Request | INVALID_DATA_REFERENCE_URI | La URI a los datos firmados no es valida |
| `610301` | PdfErrorCode.Request | INVALID_SIGNATURE_POSITION | La posicion para la firma visible en la pagina no es valida |
| `610302` | PdfErrorCode.Request | INVALID_SIGNATURE_PAGE | La pagina para la firma visible no es valida |
| `620009` | SimpleErrorCode.Request | UNSUPPORTED_REQUEST_SCHEME | El esquema de la URL de invocacion no esta soportado |
| `620010` | SimpleErrorCode.Request | INVALID_SESSION_ID | El identificador de sesion del websocket es incorrecto |
| `620011` | SimpleErrorCode.Request | UNSUPPORTED_PROTOCOL_VERSION | Version de protocolo de comunicacion con el navegador no soportada |
| `620012` | SimpleErrorCode.Request | REQUEST_URI_NOT_FOUND | No se ha proporcionado la URI de invocacion |
| `620013` | SimpleErrorCode.Request | PORTS_NOT_FOUND | No se han proporciona los puertos de conexion |
| `620016` | SimpleErrorCode.Request | MALFORMED_REQUEST_TO_SOCKET | Los parametros recibidos en el socket no son correctos |

`⎵` marks a leading space that is part of the description (two codes), producing a double space after ` - `
on the wire.

---

## Appendix B — Legacy `SAF_NN` codes (protocol < 4.1)

Wire format `SAF_NN: <message>` (one space after the colon); cancellation is the bare token `CANCEL`. The AF code
of the error is mapped through this table; codes not listed map to `SAF_53`. Messages below are the `es_ES`
(default) and `en_US` texts; other locales come from the app's message bundles.

| SAF | AF codes mapped to it | Message es_ES | Message en_US |
|---|---|---|---|
| `CANCEL` | 500001 | `CANCEL` (no message) | — |
| `SAF_00` | 200003 | No se han podido leer los datos a firmar | Data to be signed could not be read |
| `SAF_01` | 620012 | La URL recibida es nula | The URL received is null |
| `SAF_02` | 620009 | Protocolo no soportado | Protocol not supported |
| `SAF_03` | 200115, 200201, 200305, 200413, 200600, 420502, 600009, 600100, 600101, 600102, 600104, 600106, 600107, 600110, 600111, 600112, 600113, 600116, 600117, 600118, 600120, 600121, 600200, 600201, 600202, 600300, 600301, 600302, 600303, 600304, 600306, 600307, 600402, 600403, 600405, 600406, 600410, 600411, 600413, 600415, 600417, 600420, 600501, 600701, 600702, 620013, 620016 | Error en los parámetros de entrada | Error in input parameters |
| `SAF_04` | 600002 | Operación no soportada. Compruebe que dispone de la última versión de Autofirma. | Operation not supported. Check that you have the latest version of Autofirma. |
| `SAF_05` | 200301 | No se ha podido guardar los datos | Data could not be saved |
| `SAF_06` | 600105 | Formato de firma no soportado | Unsupported signature format |
| `SAF_08` | 201101 | Error accediendo al almacén de claves y certificados | Error accessing the key and certificate store |
| `SAF_09` | 200111, 200118 | Error realizando la firma electrónica | Error making the electronic signature |
| `SAF_11` | 401200, 420501 | Error en el envio del resultado de la operación. | Error in sending the outcome of the operation. |
| `SAF_12` | 200100, 200101, 200116, 200200, 200400, 200401, 220004 | Error en el cifrado de los datos a enviar | Error in encryption of data to be sent |
| `SAF_13` | 600010, 600119, 600203, 600305, 600412, 600414, 600416 | Se ha pedido acceso a una dirección local, pero por seguridad se ha bloqueado el acceso | Access to a local address has been requested, but for security access has been blocked |
| `SAF_14` | 200701 | `<html>La aplicaci&oacute;n est&aacute; obsoleta y no puede procesarse la petici&oacute;n.<br>Por favor, instale una versi&oacute;n actualizada y reintente el proceso de nuevo.</html>` | `<html>The application is obsolete and cannot be processed.<br>Please install an updated version and retry the process again.</html>` |
| `SAF_15` | 220002 | Error en el descifrado de los datos | Data decryption error |
| `SAF_16` | 220003, 401100, 401101, 401102, 401103, 401104, 401105 | Error al recuperar los datos del servidor intermedio | Error when recovering the data from the intermediate server |
| `SAF_17` | 501009 | Los datos proporcionados no son una firma electrónica reconocida | The data provided is not a recognized electronic signature |
| `SAF_18` | 200114 | Error al descodificar el certificado de firma | Error in decoding the certificate of signature |
| `SAF_19` | 501001, 502001, 504001 | No hay ningun certificado válido en su almacén. Compruebe las fechas de caducidad e instale un certificado válido. | There is no valid certificate in your warehouse. Check the expiration dates and install a valid certificate. |
| `SAF_20` | 200412 | Error en el procesado del lote de firma. | Error in the processing of the signature lot. |
| `SAF_21` | 620011 | La versión de Autofirma instalada no es compatible con este trámite.⏎Actualice a la última versión disponible. | The installed Autofirma version is not compatible with this procedure.⏎Upgrade to the latest available version. |
| `SAF_23` | 501008 | Se ha establecido una política de firma no válida o parámetros no compatibles con ella. | An invalid signature policy or parameters not compatible with it has been established. |
| `SAF_25` | 200601 | Error en la lectura de los datos a cargar. | Error in reading the data to be loaded. |
| `SAF_26` | 401501, 401701 | Error en la comunicación con el servicio de firma de lotes. | Error in communication with the batch signing service. |
| `SAF_27` | 200410, 200411, 300701, 300702 | El servicio informó de un error durante la firma del lote. | The service reported an error during the batch signing. |
| `SAF_28` | 510005 | El fichero no es un PDF o es un PDF no soportado. | The file is not a PDF or is an unsupported PDF. |
| `SAF_29` | 510002 | Las firmas XAdES Enveloped solo pueden realizarse sobre datos XML. | XAdES Enveloped signatures can only be performed on XML data. |
| `SAF_30` | 501002 | El formato de los datos a firmar no es adecuado para el tipo de firma seleccionado. | The format of the data to be signed is not appropriate for the type of signature selected. |
| `SAF_31` | 501006 | Los datos introducidos no se corresponden con un objeto de firma. | The data entered does not correspond to a signature object. |
| `SAF_32` | 510008 | La factura ya tiene una firma electrónica y no admite firmas adicionales. | The invoice already has an electronic signature and does not support additional signatures. |
| `SAF_33` | 212004, 212005 | La contraseña proporcionada no es válida para el PDF actual o no se proporcionó ninguna contraseña. | The password provided is invalid for the current PDF or no password was provided. |
| `SAF_34` | 212003 | El PDF contiene firmas no registradas. | The PDF contains unregistered signatures. |
| `SAF_35` | 212007 | El PDF está certificado. | The PDF is certified. |
| `SAF_38` | 510009 | El archivo que intenta firmar no es una factura electrónica reconocida. | The file you try to sign is not a recognized electronic invoice. |
| `SAF_39` | 500002 | La firma de entrada no es válida. | The entry signature is invalid. |
| `SAF_41` | 500005 | El uso de este trámite web requiere una versión más reciente de Autofirma.⏎Actualice a la última versión disponible. | The use of this web procedure requires a newer version of Autofirma.⏎Upgrade to the latest available version. |
| `SAF_43` | 501010 | Error durante la firma visible del PDF. | Error during visible signature of PDF. |
| `SAF_44` | 510001 | La firma no contiene los datos y no se compatible con la configuración seleccionada | The signature does not contain the data and is not compatible with the selected configuration |
| `SAF_45` | 220001 | No se pudo abrir un socket para la comunicación con la aplicación | Unable to open a socket for communication with the application |
| `SAF_46` | 620010 | Id de sesión inválido | Invalid Session Id |
| `SAF_48` | (none — unreachable; key missing → `!ProtocolLauncher.63!`) | | |
| `SAF_49` | (none — unreachable; key missing → `!ProtocolLauncher.64!`) | | |
| `SAF_51` | 200110 | El tipo de clave del certificado no está soportado. | The type of certificate key is not supported. |
| `SAF_52` | 511003, 511004 | El almacen de claves esta bloqueado | The keystore is locked |
| `SAF_53` | any other code | Error desconocido | Unknown error |

`⏎` = a real line feed inside the message. Notes: 200115 is first associated with `SAF_09` and later
re‑associated with `SAF_03` (the later association wins). 200118 is shared by two names (both `SAF_09`).
501001 is shared (core `CERTIFICATE_NEEDED` and `NO_CERTS_FOUND_SIGNING`). Codes 600102, 600118, 600119, 600202,
600203, 600304, 600305 and 600403 are defined and mapped but never raised by the current code (the parameter
parsers use the batch codes 600402/600411/600412 for every operation).

---

## Appendix C — AutoScript error codes and response mapping (page side)

Error codes generated by the page itself (`AS` prefix):

| Code | Type passed to `errorCallback` | Message |
|---|---|---|
| AS200007 | — | Error al cifrar los datos para el envio al cliente de firma |
| AS200008 | java.lang.Exception | Error al descifrar los datos recibidos del cliente de firma |
| AS220005 | — | Su navegador no permite preprocesar los datos que desea tratar |
| AS220006 | java.lang.Exception | Respuesta no valida (load result without `:`) |
| AS220007 | — | Su navegador no permite obtener el resultado de la operacion |
| AS300302 | java.lang.IOException | Ocurrio un error al enviar los datos al servicio intermedio para la comunicacion con la aplicacion nativa |
| AS400003 | java.lang.IOException | No se pudo conectar con el servidor remoto |
| AS420002 | java.lang.InterruptedException | Autofirma se ha cerrado o ha cerrado el websocket de comunicacion |
| AS420503 | java.lang.IOException | Se ha perdido la conexion con la aplicacion Autofirma |
| AS420504 | java.lang.IOException | Ocurrio un error de red en la llamada al servicio de firma |
| AS420505 | java.lang.IOException | Ocurrio un error de red en la llamada al servicio de firma |
| AS500001 | es.gob.afirma.core.AOCancelledOperationException | Operacion cancelada por el usuario |
| AS500008 | java.lang.UnsupportedOperationException | La operacion de carga de fichero no esta disponible por servidor intermedio |
| AS500009 | java.lang.UnsupportedOperationException | La operacion de carga de multiples ficheros no esta disponible por servidor intermedio |
| AS500010 | java.lang.UnsupportedOperationException | El metodo JavaScript no se encuentra operativo |
| AS600101 | java.lang.IllegalArgumentException | No se ha indicado la direccion del servlet para la recuperacion de datos |
| AS600102 | java.lang.IllegalArgumentException | No se ha indicado la direccion del servlet para el guardado de datos |
| AS620014 | java.lang.IllegalArgumentException | La URL de invocacion al servicio de firma es demasiado larga |
| AS620015 | java.lang.IOException | Ocurrio un error al enviar los datos a la aplicacion nativa |
| AS620017 | es.gob.afirma.standalone.ApplicationNotFoundException / java.util.concurrent.TimeoutException | Ha ocurrido un error al intentar invocar a la aplicacion nativa mediante websocket |
| AS620018 | es.gob.afirma.core.OutOfMemoryError | El fichero que se pretende firmar o guardar excede de la memoria disponible para aplicacion |
| AS620019 | java.lang.Exception | Error desconocido (WebSocket: `NULL` or unexpected save reply) |
| AS620020 | es.gob.afirma.standalone.ApplicationNotFoundException | Ha ocurrido un error al intentar invocar a la aplicacion nativa mediante socket |
| AS620021 | java.lang.OutOfMemoryError / es.gob.afirma.core.OutOfMemoryError | Problema de memoria en servidor |
| AS620022 | java.lang.Exception | Error desconocido (service mode) |
| AS620023 | es.gob.afirma.standalone.ApplicationNotFoundException | Ha ocurrido un error al intentar invocar a la aplicacion nativa mediante servidor intermedio |
| AS620024 | java.util.concurrent.TimeoutException | El tiempo para la recepcion de la firma por la pagina web ha expirado |
| AS620025 | java.lang.IOException | Error al conectar con el servicio de la aplicacion para recuperar el resultado de la operacion |

Response interpretation order used by AutoScript (WebSocket mode; the other modes are equivalent where
applicable):
1. `undefined`/`null`/`CANCEL` (server mode also `CANCEL\r\n`, `CANCEL\n`) → AS500001.
2. `#wait` → `getresult?idsession=<id>` after 2 s (WebSocket); in server mode `#wait` (case‑insensitive) resets
   the poll counter and `ERR-06` means "keep polling".
3. `err-NN:=` (case‑insensitive `err-`, then `:=`) → error; `err-11:` → cancellation type; if the text after `:=`
   has `" - "` at offset 8 → code = first 8 chars, message = rest; else message = whole rest.
4. `MEMORY_ERROR` → AS620018 / AS620021.
5. `SAF_…` (length > 4) → `java.lang.Exception` with the raw string (WebSocket: as the *code* argument).
6. `NULL` → AS620019/AS620022.
7. Per operation: save → `OK`/`SAVE_OK`; load → `name:b64` items; selectcert → cert; batch → `result|cert`
   (`JSON.parse(Base64.decode(result))` attempted); sign family → `cert|sig[|extra]` (service mode does not split
   `extra`). URL‑safe Base64 converted back with `-`→`+`, `_`→`/`. Server mode decrypts every `|` field first.
