# 05 — Key stores, smart cards and certificate selection

Status: implementation spec for the Rust re-implementation of AutoFirma (Cliente @firma 1.9.x / 1.10).
Audience: a Rust developer who will **not** read the Java sources.
Scope: every key store type, how each one is discovered/opened/used to sign, smart-card (DNIe/CERES) handling,
PIN prompts and caching, certificate filters, the certificate selection dialog, store selection logic
(protocol, CLI, local GUI), related preferences, error codes, and a parity checklist.

Java modules analysed (paths relative to repo root):

| Module | What it contains |
|---|---|
| `afirma-core-keystores` | `AOKeyStore` enum, `AOKeyStoreManager(+Factory)`, aggregated stores, Windows/macOS/PKCS#12/PKCS#11 managers, `KeyStoreUtilities`, `AOKeyStoreDialog`, error codes, password callbacks |
| `afirma-keystores-mozilla` | Firefox/NSS discovery, `profiles.ini`, `pkcs11.txt`/`secmod.db`, NSS init, shared NSS DB |
| `afirma-keystores-filters` | `CertFilterManager` + all certificate filters |
| `afirma-keystores-jmulticard-ui` | PIN / CAN / confirmation dialogs and PIN cache for the 100%-Java DNIe/CERES driver (jmulticard 2.1) |
| `afirma-ui-core-jse-keystores` | Swing certificate selection dialog |
| `afirma-keystores-capiaddressbook`, `afirma-keystores-single` | Obsolete Windows "other people"/CA stores; PKCS#7/X.509 file store |
| `afirma-simple` (`SimpleKeyStoreManager*`, `CommandLineLauncher`, `protocol/*`, `ui/SignPanel*`, `ui/preferences/PreferencesPanelKeystores`, `ui/tasks/LoadKeystoreTask`) | Store selection logic, CLI, preferences UI |
| `afirma-core-prefs` (`KeyStorePreferencesManager`) | Registered smart cards, "last selected store" |
| `afirma-ui-simple-configurator-common` (`PreferencesManager`, `preferences.properties`) | Preference keys and defaults |

Conventions in this document:
- "**Java:**" describes exact current behaviour (parity target). "**Rust:**" is the recommended implementation.
- "**Quirk/Bug:**" marks Java behaviour that is surprising; the spec says whether to reproduce it.
- Spanish UI strings are quoted verbatim (`es_ES` bundle) with the message key; other locales exist (`ca_ES`, `en_US`, `eu_ES`, `gl_ES`, `va_ES`) and must be ported as resources.

---

## 0. Architecture overview

```
                     +------------------------------------+
 protocol / CLI /    |  Store selection (section 9)       |
 local GUI  ------>  |  -> AOKeyStore id + optional "lib" |
                     +-----------------+------------------+
                                       v
                     +------------------------------------+
                     | AOKeyStoreManagerFactory           |  builds an AggregatedKeyStoreManager
                     +-----------------+------------------+
                                       v
   AggregatedKeyStoreManager = ordered list of sub-managers, e.g.
     Windows:  [ CAPI "MY" , (DNIe-Java | CERES430-Java | CERES-Java)? ]
     macOS:    [ Keychain  , (DNIe/CERES Java)? ]
     Firefox:  [ NSS softokn internal slot , (DNIe/CERES Java)? | first working external PKCS#11 module ]
     Firefox+OS (browser calls): [ NSS internal , OS store , DNIe/CERES Java? | external PKCS#11 ]
     PKCS#12 / PKCS#11 / DNIe: single sub-manager
                                       v
              alias list -> filters (section 7) -> friendly names (CN) -> selection dialog (section 8)
                                       v
              PrivateKeyEntry (key handle + chain) -> signer computes "<HASH>with<RSA|ECDSA>" over data
```

Key concepts the Rust code must reproduce:

1. **Sub-store aggregation**: a "store" shown to the user is the union of several backends.
2. **Preferred stores** (DNIe/CERES via the built-in Java driver): when added to an aggregate, every certificate
   they contain is **deactivated** (hidden) in all previously added backends, matched by SHA-1 thumbprint
   (uppercase hex, no separators). This removes duplicates that appear through Windows minidrivers, Firefox PKCS#11
   modules, etc.
3. **Aliases** are backend-native strings; the dialog shows a **friendly name** (subject CN).
4. **Filters** decide which aliases are offered.
5. **Signing** is always "sign these bytes with `SHAxxxwithRSA` / `SHAxxxwithECDSA`" (never raw-hash from the
   caller's point of view), followed by a verification of the produced signature with the certificate public key.

---

## 1. Key store types

### 1.1 Master table

Store identifiers: the protocol and preferences resolve a store either by **display name** (`getName()`,
case-insensitive, trimmed) or by **enum constant name** (`AOKeyStore.valueOf`, case-sensitive, exact). See 9.1.

Password callback abbreviations: `Null` = returns null password; `Cache("x")` = constant password `x`;
`UI(k)` = interactive password dialog with message key `AOKeyStore.k`; `—` = no callback (driver asks itself).

| Enum constant (protocol id) | Display name `getName()` (exact) | JCA type | ord. | Store pwd | Entry pwd | Opened by factory? | OS | Java implementation | Rust equivalent |
|---|---|---|---|---|---|---|---|---|---|
| `WINDOWS` | `Windows` | `Windows-MY` | 0 | `Null` | `Cache("winmydummy")` | yes, Windows only | Win | `CAPIUnifiedKeyStoreManager` = `CAPIKeyStoreManager` (SunMSCAPI) + preferred cards | `windows` crate: `CertOpenStore(CERT_STORE_PROV_SYSTEM_W, …, CERT_SYSTEM_STORE_CURRENT_USER, "MY")`, `CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG …)`, `NCryptSignHash` / legacy `CryptSignHash` (3.1) |
| `APPLE` | `Llavero de Mac` | `KeychainStore` | 1 | `Cache("osxdummy")` | `Cache("osxdummy")` | yes, macOS only | mac | `AppleKeyStoreManager` (JDK `Apple` provider) + preferred cards | `security-framework`: `SecItemCopyMatching(kSecClassIdentity)`, `SecKeyCreateSignature` (3.3) |
| `SHARED_NSS` | `NSS` | `PKCS11` | 2 | `UI(13)` | `Null` | yes, **Linux only** | Lin | `SharedNssKeyStoreManager` (NSS softokn on `~/.pki/nssdb`) + preferred + external PKCS#11 | NSS softokn via PKCS#11 or `libnss3` FFI (3.6) |
| `PKCS12` | `PKCS#12 / PFX` | `PKCS12` | 3 | `UI(1)` (prompt customised with file name, `AOKeyStore.15`) | `UI(0)` | yes | all | `Pkcs12KeyStoreManager` | PKCS#12 parser (`p12-keystore`/`openssl`), software RSA/ECDSA (3.4) |
| `JAVA` | `Java KeyStore / JKS` | `JKS` | 5 | `UI(3)` | `UI(2)` | yes | all | `JavaKeyStoreManager` | optional: JKS parser; low priority |
| `PKCS11` | `PKCS#11` (**mutable**, see quirk) | `PKCS11` | 6 | `UI(4)` (prompt `AOKeyStore.15` with "PKCS#11") | `Null` | yes (needs `lib`) | all | `AOKeyStoreManagerHelperPkcs11` (SunPKCS11) | `cryptoki` crate (3.5) |
| `SINGLE` | `PKCS#7 / X.509` | `PKCS7` | 7 | `Null` | `Null` | yes (file) | all | `SingleCertKeyStore` (certs only, no keys) | parse `.cer`/`.p7b`; never selectable for signing |
| `MOZ_UNI` | `Mozilla / Firefox (unificado)` | `PKCS11` | 8 | `UI(5)` | `Null` | yes | all | `MozillaUnifiedKeyStoreManager` | NSS + external PKCS#11 + preferred cards (3.6) |
| `MOZ_UNI_WITH_OS` | `Mozilla / Firefox (unificado) junto a almacen de SO` | `PKCS11` | 8 | `UI(5)` | `Null` | yes | all | `MozillaUnifiedWithOSKeyStoreManager` (MOZ_UNI + Windows/macOS OS store) | same as MOZ_UNI plus OS backend |
| `JCEKS` | `Java Cryptography Extension KeyStore (JCEKS)` | `JCEKS` | 9 | `UI(7)` | `UI(6)` | yes (file) | all | generic `AOKeyStoreManager` | optional |
| `JAVACE` | `Java KeyStore / JKS (Case Exact)` | `CaseExactJKS` | 10 | `UI(9)` | `UI(8)` | yes (file) | all | generic | optional |
| `TEMD` | `TEMD (Tarjeta del Ministerio de Defensa)` | `PKCS11` | 11 | `UI(14)` | `—` | **no** → `UNSUPPORTED_KEYSTORE` | — | none | reject like Java |
| `WINADDRESSBOOK` | `Windows / Internet Explorer (otras personas / libreta de direcciones)` | `Windows-ADDRESSBOOK` | 12 | `Null` | `Cache("winotherdummy")` | yes, Windows | Win | `MSCAPIAddressBook` provider (obsolete; public certs only) | `CertOpenStore(..."AddressBook")`; optional |
| `WINCA` | `Windows / Internet Explorer (CA intermedias)` | `Windows-ROOT` | 13 | `Null` | `Cache("wincadummy")` | yes, Windows | Win | **Bug:** provider registers `Windows-CA`, enum asks `Windows-ROOT` → always fails | optional (`"CA"` system store) |
| `CERES` | `Tarjeta FNMT-RCM CERES` | `CERES` | 14 | `—` | `—` | yes | all (PC/SC) | jmulticard `CeresProvider` | PC/SC (`pcsc` crate) + card driver (3.7) |
| `DNIEJAVA` | `DNIe y tarjetas FNMT-TIF` | `DNI` | 15 | `—` | `—` | yes | all (PC/SC) | jmulticard `DnieProvider` | PC/SC + DNIe driver (3.7) |
| `KNOWN_SMARTCARDS` | `Tarjetas inteligentes conocidas mediante PKCS#11` | `SMARTCARDS` | 16 | `—` | `—` | only internally (Windows temporary profile) | Win | `SmartCardUnifiedKeyStoreManager` | (3.8) |
| `SMARTCAFE` | `G&D SmartCafe con Applet PKCS#15` | `GDSCPKCS15` | 17 | `—` | `—` | yes | all | jmulticard `SmartCafeProvider` (only probed if enabled by env) | optional |
| `CERES_430` | `Tarjeta FNMT-RCM CERES 4.30 o superior` | `CERES430` | 18 | `—` | `—` | yes | all | jmulticard `DnieProvider` configured with `name=JMulticard\nallowAnotherCards=true` | (3.7) |
| `OTHER` | `Tipo desconocido` | null | 18 | — | — | **no** | — | — | reject |

Notes:
- Ordinals are internal; never exposed in protocol.
- **There is no cloud/Cl@ve/FIRe store and no `TIF` enum value** in this code base. "FNMT-TIF" cards are covered by
  `DNIEJAVA` (jmulticard) and the native FNMT PKCS#11 libraries (`TIF_P11.dll`).
- **Quirk (`PKCS11` name mutation):** `AOKeyStore.PKCS11.setName(cardName)` is called whenever a user-registered
  smart card is used; the enum's display name becomes that card name for the rest of the process. Rust: model a
  registered card as its own value (`StoreId::Pkcs11 { name, lib }`), do not mutate globals.

### 1.2 Default store per OS (`AOKeyStore.getDefaultKeyStoreTypeByOs`)

| OS | Default |
|---|---|
| Windows | `WINDOWS` |
| macOS | `APPLE` |
| Linux | `SHARED_NSS` |
| Solaris | `MOZ_UNI` |
| other | `null` (Java would NPE later) → Rust: return error `UNDEFINED_DEFAULT_KEYSTORE` (201116) |

The "system" entry of the in-dialog store switcher (`openSystemKeyStore`) maps Windows→`WINDOWS`,
Linux/Solaris→`SHARED_NSS`, macOS→`APPLE`, else `KeystoreAlternativeException(UNDEFINED_DEFAULT_KEYSTORE)`.

### 1.3 Factory dispatch (`AOKeyStoreManagerFactory.getAOKeyStoreManager(store, lib, description, pwdCallback, parent)`)

Evaluated in this exact order:

1. `PKCS12` → PKCS#12 manager on file `lib` (file chooser if `lib` is null/empty/non-existent; filter `*.pfx, *.p12`,
   title `"Abrir repositorio PKCS#12 / PFX"` = `AOKeyStoreManagerFactory.4` + " " + display name).
2. `JAVA` → JKS on `lib` (chooser `*.jks`).
3. `SINGLE`/`JAVACE`/`JCEKS` → file store (chooser `*.cer, *.p7b` or `*.jceks, *.jks, *.jce`).
4. `PKCS11` → PKCS#11 with library `lib`. If `lib` given but not a file → `IOException("La biblioteca '<lib>' no existe")`.
   If `lib` null → file chooser `"Seleccionar biblioteca PKCS#11"`, filter `*.dll` (Win) / `*.so, *.dylib` (mac) / `*.so`.
5. `WINDOWS` (Windows only) → `CAPIUnifiedKeyStoreManager`.
6. `WINADDRESSBOOK`/`WINCA` (Windows only).
7. `MOZ_UNI` → Mozilla unified (**process-wide cached**, see 3.6.10).
8. `MOZ_UNI_WITH_OS` → Mozilla unified + OS (shares the same cache variable as `MOZ_UNI`!).
9. `SHARED_NSS` (Linux only).
10. `APPLE` (macOS only); `lib` may point at a keychain file (ignored in practice).
11. `DNIEJAVA`, `CERES_430`, `CERES`, `SMARTCAFE` → jmulticard stores (marked *preferred*).
12. Anything else (including `WINDOWS` on Linux, `TEMD`, `OTHER`, `KNOWN_SMARTCARDS`) →
    `KeystoreAlternativeException(alternative, "La plataforma de navegador '<name>' mas sistema operativo '<OS>' no esta soportada", UNSUPPORTED_KEYSTORE 600011)`.

`KeystoreAlternativeException` carries a suggested alternative (`getAlternateKeyStoreType`): `PKCS12`→none;
on Windows any non-`WINDOWS`→`WINDOWS`; on macOS any non-`APPLE`→`APPLE`; otherwise `PKCS12`. Callers mostly
ignore it and fall back to the OS default (section 9).

Global switch: JVM property `es.gob.afirma.keystores.ForceReset=true` → never reuse cached providers/stores.
Rust: env var `AFIRMA_FORCE_STORE_RESET` (or config flag) with the same meaning.

### 1.4 Hard-coded PKCS#11 library names and paths

| Purpose | Names / paths (exact) | Where used |
|---|---|---|
| Libraries that **must not use `CKM_SHA1_RSA_PKCS`** (FNMT driver v10 bug); matched case-insensitively on file name; Java adds `disabledMechanisms={ CKM_SHA1_RSA_PKCS }` | `DNIe_P11_priv.dll`, `DNIe_P11_pub.dll`, `FNMT_P11.dll`, `FNMT_P11_x64.dll`, `UsrPkcs11.dll`, `UsrPubPkcs11.dll`, `TIF_P11.dll` | every PKCS#11 load (3.5) |
| "Native DNIe PKCS#11" libraries (matched with case-insensitive `endsWith`) — excluded from Firefox external modules when the Java DNIe driver is preferred | `libopensc-dnie.dylib`, `libpkcs11-dnie.so`, `usrpkcs11.dll`, `dnie_p11_priv.dll`, `dnie_p11_pub.dll`, `opensc-pkcs11.dll`, `DNIE_P11.dll`, `TIF_P11.dll` | 3.6.7 |
| Windows "known modules" added to the Firefox module list even if not registered in Firefox; path = `<system lib dir>\<lib>` (`System32`, or `SysWOW64` for a 32-bit process) | `Atos CardOS (preinstalado)` → `siecap11.dll` (only if file exists); `FNMT-RCM Modulo PKCS#11 64bits` → `FNMT_P11_x64.dll` (**always**, even if absent); `FNMT-RCM Modulo PKCS#11 32bits` → `FNMT_P11.dll` (**always**) | 3.6.7 |
| Windows temporary-profile fallback (`KNOWN_SMARTCARDS`), in order; env vars expanded | `FNMT-CERES` (preferred): `%SYSTEMROOT%/System32/FNMT_P11_x64.dll`, `%SYSTEMROOT%/System32/FNMT_P11.dll`, `%SYSTEMROOT%/SysWOW64/FNMT_P11.dll`; `CardOS`: `%SYSTEMROOT%/SysWOW64/siecap11.dll`, `%SYSTEMROOT%/System32/siecap11.dll`; `TUI`: `%PROGRAMFILES%/umu/Third-Party/Gemalto/Classic Client/BIN/gclib.dll`, `%PROGRAMFILES(x86)%/umu/Third-Party/Gemalto/Classic Client/BIN/gclib.dll`, `%PROGRAMFILES%/umu/UMU-Crypto/lib/libumupkcs11.dll`, `%PROGRAMFILES(x86)%/umu/UMU-Crypto/lib/libumupkcs11.dll`, `%PROGRAMFILES%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS1164.dll`, `%PROGRAMFILES%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS11.dll`, `%PROGRAMFILES(x86)%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS1164.dll`, `%PROGRAMFILES(x86)%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS11.dll`; `SafeSign`: `%SYSTEMROOT%/SysWOW64/aetpkss1.dll`, `%SYSTEMROOT%/System32/aetpkss1.dll` | 3.8 |
| NSS root-certificate module, always dropped from external module lists | any library path containing `nssckbi` (case-insensitive) | 3.6.7 |

There are **no hard-coded PKCS#11 paths for Linux/macOS** (no `opensc-pkcs11.so` default, no FNMT `.so`);
on those OSes external modules come only from Firefox/NSS `pkcs11.txt`/`secmod.db` or user-registered cards.
Rust improvement (optional, off by default for parity): probe well-known paths
(`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`, `/usr/lib64/opensc-pkcs11.so`, `/usr/lib/libpkcs11-dnie.so`,
`/Library/OpenSC/lib/opensc-pkcs11.so`, `/usr/local/lib/libpkcs11-fnmtdnie.so`…) when no store finds a card.

### 1.5 Environment variables / system properties affecting stores

Java reads both a JVM system property and an OS env var for most switches (`Boolean.getBoolean(prop) || Boolean.parseBoolean(getenv(ENV))`; value must be `true`, case-insensitive). Rust: read the **env var** names; optionally accept the property names in a config file.

| Env var | Java property | Effect |
|---|---|---|
| `AFIRMA_NSS_DISABLE_DNIE_NATIVE_DRIVER` | `es.gob.afirma.keystores.mozilla.disableDnieNativeDriver` | Do not probe DNIe with the built-in driver. (Property only, when true, also stops treating native DNIe P11 libs as "DNIe" in 3.6.7.) |
| `AFIRMA_NSS_DISABLE_CERES_NATIVE_DRIVER` | `es.gob.afirma.keystores.mozilla.disableCeresNativeDriver` | Do not probe CERES / CERES 4.30 with the built-in driver |
| `AFIRMA_NSS_ENABLE_GYDSC_NATIVE_DRIVER` | `es.gob.afirma.keystores.mozilla.enableGYDSCNativeDriver` | Probe G&D SmartCafe (off by default) |
| `AFIRMA_NSS_LOAD_SSCD_ONLY` | `es.gob.afirma.keystores.mozilla.LoadSscdOnly` | Mozilla stores: skip NSS internal soft store, only cards/external modules |
| `AFIRMA_NSS_INCLUDE_NATIVE_DNIE_PKCS11` | `es.gob.afirma.keystores.mozilla.IncludeNativeDniePkcs11` | Dead code in practice (see 3.6.11) |
| `es.gob.afirma.keystores.mozilla.UseEnvironmentVariables` (env or property) | same | Enables `AFIRMA_NSS_PROFILES_INI` (and property-only `AFIRMA_NSS_HOME_ENV`) |
| `AFIRMA_NSS_PROFILES_INI` (env, or property of that name) | — | Explicit path to Firefox `profiles.ini`; `%APPDATA%` (case-insensitive) expanded; ignored if not a readable file |
| `AFIRMA_NSS_HOME_ENV` | — | Intended NSS lib dir override; **Bug:** value is immediately overwritten by OS detection → no effect. Rust: honour it (improvement) |
| — | `es.gob.afirma.keystores.mozilla.EnableNssWrite` | Open NSS read-write (omit `flags='readOnly'`) |
| `NSS_DEFAULT_DB_TYPE` = `sql` | — | Force SQLite NSS DB mode (`sql:/` prefix, read `pkcs11.txt`) |
| — | `es.gob.afirma.keystores.DoNotReusePkcs11Provider` | Re-create PKCS#11 provider every time |
| — | `es.gob.afirma.keystores.ForceReset` | See 1.3 |
| `USERPROFILE` + `user.name` | — | Windows temporary profile detection (3.1.2) |

The preference `enabledJmulticard` (default `true`) is applied at start of every protocol invocation and of the
local app: `false` sets both DNIe/CERES *disable* properties; `true` clears them (env vars still apply).

---

## 2. Common store manager contract (what Rust must provide)

Every backend implements (Java `AOKeyStoreManager` / `KeyStoreManager`):

| Operation | Semantics |
|---|---|
| `init(type, stream, storePwdCallback, params, forceReset)` | Open/load. May prompt. Errors: wrong password → `IOException` whose cause chain contains `UnrecoverableKeyException` (Rust: `Error::WrongPassword`); cancel → `AOCancelledOperationException` (`Error::Cancelled`). |
| `getAliases()` | Cached after first call (`cachedAliases`), minus **deactivated** thumbprints. Errors → empty list (logged). |
| `getCertificate(alias)` | X.509 or null (never throws, except card-driver cancellation → `Cancelled`). |
| `getCertificateChain(alias)` | Array of X.509 (non-X.509 elements dropped); empty array if unknown. |
| `isKeyEntry(alias)` | True iff a usable private key exists. |
| `getKeyEntry(alias)` | Private key handle + chain. Entry password: explicit `entryPasswordCallback` if set, otherwise the store type's certificate callback (table 1.1). |
| `refresh()` | Re-init with `forceReset=true`; on failure the backend's key store becomes null and its entries disappear ("se ocultaran sus entradas"). |
| `deactivateEntry(sha1HexUpper)` | Hide a certificate (used by preferred-store de-duplication). |
| `getType()` | Store type; aggregated managers report the first sub-manager's type when unset. |

**Aggregated manager** (`AggregatedKeyStoreManager`):
- `getAliases()` = concatenation of sub-manager alias lists in insertion order (sub-managers that throw are skipped).
- `getCertificate/getKeyEntry/getCertificateChain/isKeyEntry(alias)` = first sub-manager whose alias list
  **contains** the alias. **Quirk:** identical alias strings in two sub-stores collide (the second is unreachable).
  Rust: namespace aliases internally (`<backend-index>:<native-alias>`), keep native alias for CLI output.
- `addKeyStoreManager(ksm)`: if `ksm` is *preferred*, for each of its certificates compute SHA-1 of DER, uppercase
  hex, and call `deactivateEntry` on every already-added sub-manager; then append.
- `refresh()`: refresh every sub-manager; a failing one is emptied, others continue.

---

## 3. Per-store behaviour

### 3.1 Windows certificate store (`WINDOWS`)

#### 3.1.1 Java behaviour
- `CAPIUnifiedKeyStoreManager.init`:
  1. Empty the aggregate.
  2. If **not** a temporary profile: create `CAPIKeyStoreManager` (SunMSCAPI `Windows-MY`, i.e. CurrentUser\MY).
     Load errors are logged and the (empty) manager is still added.
  3. If `forceReset || first init`: `addPreferredKeyStoreManagers` (3.7.2). If the user **cancels** a card PIN/CAN
     there, treat as "preferred present" (no further card probing).
  4. If temporary profile **and** no preferred store: add `SmartCardUnifiedKeyStoreManager` (3.8).
  5. If the CAPI store was loaded **and** no preferred store was found: `capiKsm.refresh()` (re-open "MY") because
     probing the card with the Java driver steals the reader connection from the Windows minidriver.
- `CAPIKeyStoreManager` keeps the loaded `KeyStore` in a **static** (process-wide); `forceReset` clears it.
- Load uses a `KeyStore.Builder` with a callback handler whose password callback is
  `FirstEmptyThenPinUiPasswordCallback("Por favor, introduzca la contraseña de su dispositivo criptográfico")`
  (`CAPIKeyStoreManager.0`). **Quirk:** its `isFirstTime` is a constant `true`, so it always answers an empty
  password → PIN UI is always delegated to the CSP/KSP (Windows smart-card PIN dialog).
- Private key: `getEntry(alias, PasswordProtection("dummy"))`.
- Duplicate aliases (only Java < 9): appended `" - " + certHashCode`. Not needed in Rust.
- A certificate is a "key entry" only if SunMSCAPI could acquire its private key while enumerating
  (card must be present); others become trusted-cert entries and are hidden by the private-key check.

#### 3.1.2 Temporary profile detection
`user.name` and env `USERPROFILE` must both exist; `profileName = basename(USERPROFILE)`;
temporary iff `user.name != profileName` **and** (`profileName == "TEMP"` or `profileName` starts with `"TEMP."`).
On a temporary profile the CAPI store is skipped entirely.

#### 3.1.3 Rust implementation
- Open: `CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, w!("MY"))`.
- Enumerate with `CertEnumCertificatesInStore`. Key presence: `CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID)`;
  for parity with SunMSCAPI also try `CryptAcquireCertificatePrivateKey(ctx, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, …)`;
  treat success or `NTE_SILENT_CONTEXT` as "has key", `SCARD_W_REMOVED_CARD`/`NTE_BAD_KEYSET`/`SCARD_E_NO_SMARTCARD` as "no key" (hidden).
- Alias: SunMSCAPI uses the certificate friendly name property (`CERT_FRIENDLY_NAME_PROP_ID`), falling back to
  `CertGetNameStringW(CERT_NAME_FRIENDLY_DISPLAY_TYPE)`; Java 11+ makes duplicates unique by appending
  `" (1)"`, `" (2)"`… (OpenJDK behaviour, not in this repo). Reproduce this for CLI `-alias` compatibility.
- Chain: `CertGetCertificateChain(HCCE_CURRENT_USER, …)`; first simple chain, end-entity first; if it fails
  return just the end-entity certificate.
- Signing: acquire key without `SILENT` (lets the KSP/CSP show its PIN UI):
  - **CNG** handle: hash in-process; `NCryptSignHash(key, &BCRYPT_PKCS1_PADDING_INFO{pszAlgId: BCRYPT_SHA256_ALGORITHM…}, hash, …, BCRYPT_PAD_PKCS1)` for RSA;
    for ECDSA `NCryptSignHash(…, flags 0)` returns `r||s` → convert to DER `SEQUENCE{INTEGER r, INTEGER s}`.
  - **Legacy CAPI** handle (`HCRYPTPROV` + `AT_SIGNATURE/AT_KEYEXCHANGE`): `CryptCreateHash(CALG_SHA_256…)`,
    `CryptSetHashParam(HP_HASHVAL)`, `CryptSignHash(keySpec)`, **reverse the output bytes** (CAPI is little-endian).
    If the CSP is `PROV_RSA_FULL` and lacks SHA-2, re-acquire via `CryptAcquireContext(…, MS_ENH_RSA_AES_PROV, PROV_RSA_AES)` with the same container (what SunMSCAPI does), or prefer `CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG`.
- PIN errors: `SCARD_W_WRONG_CHV` → `PinIncorrect`; `SCARD_W_CHV_BLOCKED` → `Locked`; `SCARD_W_CANCELLED_BY_USER`/`ERROR_CANCELLED` → `Cancelled`.

### 3.2 Windows "other people" / CA stores (obsolete)
`WINADDRESSBOOK` opens CAPI `ADDRESSBOOK`, `WINCA` intends CAPI `CA` (broken, 1.1). Public certificates only;
never usable for signing. Rust: implement `ADDRESSBOOK` and `CA` read-only if needed by other features
(encryption recipient selection); not used by AutoFirma signing flows.

### 3.3 macOS Keychain (`APPLE`)

#### 3.3.1 Java behaviour
- `KeyStore.getInstance("KeychainStore").load(null|fileStream, null)` (default keychain search list).
- Alias list computed once at init: aliases where `isKeyEntry` is true, then **de-duplicated by certificate serial
  number** (first alias per serial wins; certificates that cannot be read are dropped).
- `getKeyEntry`: `getKey(alias, "dummy")`; if null → `UnsupportedOperationException("La entrada no tiene clave privada")`.
  The JDK KeychainStore **exports** the private key (wrapped PKCS#8) and signs in software, so keys that are
  not exportable (CryptoTokenKit smart cards, Secure Enclave) are listed but **fail at signing**, and the user sees
  macOS "allow export" prompts.
- `getMacOSXKeyStoreManager` wraps it in an aggregate and calls `addPreferredKeyStoreManagers` (DNIe/CERES);
  cancellation of the card driver is logged and ignored.

#### 3.3.2 Rust implementation
- `SecItemCopyMatching({kSecClass: kSecClassIdentity, kSecMatchLimit: kSecMatchLimitAll, kSecReturnRef: true, kSecReturnAttributes: true})`.
  Alias = identity label (`kSecAttrLabel`, as Java). Keep the serial-number de-duplication.
- Signing with `SecKeyCreateSignature` (no export): RSA `kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA{1,256,384,512}`;
  EC `kSecKeyAlgorithmECDSASignatureMessageX962SHA{…}` (already DER). Improvement over Java: works with
  token/non-exportable keys; prompts are the native keychain/PIN prompts.
- Improvement (optional flag): include CryptoTokenKit identities (`kSecAttrTokenID`), which Java does not see.

### 3.4 PKCS#12 file (`PKCS12`) and other file stores

#### 3.4.1 Java behaviour
- File: `lib` if it exists, else file chooser (`AOKeyStoreDialog.6` "Selección de almacén local", filter
  `"Almacenes de claves (*.p12, *.pfx)"` from the dialog; factory uses `"Almacenes PKCS#12 (*.p12, *.pfx)"`).
- Store password prompt: if file known → `"Introduzca la contraseña del almacén <fileName>."` (`AOKeyStore.15`),
  else `"Introduzca la contraseña del almacén PKCS#12."` (`AOKeyStore.1`). Empty password allowed.
- The store password is cached in memory for the manager lifetime (`CachePasswordCallback`) and reused by `refresh()`
  (which re-reads the same file).
- Wrong password: `ks.load` fails with cause `UnrecoverableKeyException` / `BadPaddingException` /
  `ArithmeticException` → `IOException("La contrasena del almacen PKCS#12 / PFX no es valida")`; other failures →
  `IOException("El almacen PKCS#12 / PFX no es valido o no pudo cargarse")`.
- Private key password order: (1) store password, (2) null/empty, (3) prompt
  `"Introduzca la contraseña del certificado dentro del fichero PKCS#12."` (`AOKeyStore.0`).
- Retry loops on wrong password exist **only** in interactive paths: in-dialog "change store → PKCS#12"
  (`AOKeyStoreDialog`: shows `"Contraseña incorrecta."` titled `"Error"` and re-prompts until success/cancel) and
  local-GUI default-store load (`SimpleKeyStoreManager`: shows `"Contraseña incorrecta"`, re-prompts; cancel →
  `"Operación cancelada. Se cargará el almacén de claves del sistema."` and OS store). Protocol-requested PKCS#12
  with a wrong password fails immediately with `LOADING_KEYSTORE_INTERNAL_ERROR` (SAF_08).
- Aliases: Java PKCS12KeyStore uses the bag `friendlyName`; when absent it synthesises `"1"`, `"2"`… (OpenJDK).
- `JAVA`/`JCEKS`/`JAVACE`: same model with Java formats. `SINGLE`: X.509 or PKCS#7 file, aliases = subject CN,
  no private keys.

#### 3.4.2 Rust implementation
Parse PKCS#12 (PBES1/PBES2, legacy RC2/3DES and AES; MAC SHA-1/SHA-256). Sign in software (`rsa`, `p256`/`p384`/`p521`
crates or OpenSSL). Zeroize passwords and key material after use. Reproduce the three-step key password order.

### 3.5 Generic PKCS#11 (`PKCS11`, registered cards, Firefox external modules)

#### 3.5.1 Java behaviour (SunPKCS11)
- Library path resolution: if relative and not a file, search `java.library.path`; on Windows, if the path contains
  `(` or `)` convert it to an 8.3 short name (`cmd /c for %f in ("<path>") do @echo %~sf`). Rust: not needed
  (load with `LoadLibraryExW` and the full path; use `LOAD_WITH_ALTERED_SEARCH_PATH` so dependent DLLs next to the module resolve).
- Provider config written by Java:
  ```
  library=<path>\r\n
  name=<file name with '.' and ' ' replaced by '_'>      (default "AFIRMA-PKCS11")
  showInfo=true\r\n
  slot=<n>\r\n                                           (only if a slot was given; never in practice)
  disabledMechanisms={ CKM_SHA1_RSA_PKCS }\r\n           (only FNMT libs, table 1.4)
  ```
  No slot → SunPKCS11 uses `slotListIndex=0` over `C_GetSlotList(FALSE)` (**first slot even without a token**).
- Provider instances are cached per library file name and reused (PIN session survives) unless `forceReset` or
  `DoNotReusePkcs11Provider`. Initialisation is retried once if the first attempt fails ("El PKCS#11 del DNIe a veces
  falla a la primera").
- Load = **login at open time** (C_Login happens before the dialog is shown, using the store password callback).
  Prompt: `"Introduzca la contraseña del almacén PKCS#11."` (`AOKeyStore.15` with the `PKCS11` display name, i.e. the card
  name when a registered card is used); Firefox external modules
  use `"Introduzca la contraseña de <module description>"`; Windows known cards use
  `"Por favor, introduzca la contraseña de la tarjeta <name>"`.
- If the callback is null (CLI without `-password`) → `load(null, null)` without login (public objects only).
- Login errors (`LoginException` whose PKCS#11 cause message is):
  - `CKR_PIN_INCORRECT` → dialog `"La contraseña introducida no es correcta."` (`KeyStoreUtilities.5`), title
    `"Error al cargar el almacén de claves"` (`KeyStoreUtilities.6`), **retry prompting**;
  - `CKR_PIN_LEN_RANGE` → `"La longitud de la contraseña introducida no es válida."` (`.8`), retry;
  - `CKR_PIN_LOCKED` → `"Su almacén de claves esta bloqueado."` (`.7`), **no retry**, error;
  - any other `LoginException` → message `.5`, retry.
  Cancel in the PIN dialog → provider removed, `Cancelled`.
- Token messages delivered through JAAS `TextOutputCallback` are shown as dialogs titled `"Información del almacén de
  claves"` / `"Error del almacén de claves"` / `"Advertencia del almacén de claves"`; a `NameCallback` (username) is
  asked (`"Por favor, introduzca el nombre de usuario del almacén de claves."` / title `"Nombre de usuario del dispositivo
  criptográfico"`) but then rejected as unsupported.
- Aliases: SunPKCS11 aliases = `CKA_LABEL` of certificate/key pairs matched by `CKA_ID`; key entry iff a private key with
  the same `CKA_ID` exists.

#### 3.5.2 Rust implementation (`cryptoki`)
- `Pkcs11::new(path)`, `initialize(CInitializeArgs::OsThreads)`; tolerate `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
- Slot choice: **improve** on Java: iterate `get_slots_with_token()`; aggregate all token slots (each slot = sub-backend).
  Keep a parity mode that uses only the first slot of `get_all_slots()`.
- Login at open if `CKF_LOGIN_REQUIRED` and not `CKF_PROTECTED_AUTHENTICATION_PATH` (if PAP, call `C_Login` with null PIN and let the reader pad prompt).
- Use `CK_TOKEN_INFO.flags` (`CKF_USER_PIN_COUNT_LOW`, `CKF_USER_PIN_FINAL_TRY`, `CKF_USER_PIN_LOCKED`) to enrich the prompt (improvement).
- Enumerate `CKO_CERTIFICATE`/`CKC_X_509`, match `CKO_PRIVATE_KEY` by `CKA_ID`; alias = `CKA_LABEL` (UTF-8), fallback hex `CKA_ID`.
- Mechanisms: RSA → `CKM_SHA{256,384,512}_RSA_PKCS` over data if listed in `C_GetMechanismList` and not disabled;
  else `CKM_RSA_PKCS` over `DigestInfo(hash)` (Appendix B). For FNMT libs in table 1.4 never use `CKM_SHA1_RSA_PKCS`.
  EC → `CKM_ECDSA` over the hash (truncate to order length as per spec), result `r||s` → DER.
- Keep the session (and login) cached per library path for the process lifetime; `refresh` closes and re-opens.
- Retry `C_Initialize`/first `C_GetSlotList` once on failure (Linux PC/SC first-call flakiness).

### 3.6 Mozilla Firefox / NSS (`MOZ_UNI`, `MOZ_UNI_WITH_OS`, `SHARED_NSS`)

#### 3.6.1 Location of `profiles.ini`
Order:
1. If `UseEnvironmentVariables` is enabled (1.5) and `AFIRMA_NSS_PROFILES_INI` (env, else property) names a readable
   file → use it (`%APPDATA%` expanded with the Windows AppData dir).
2. Windows: `%APPDATA%\Mozilla\Firefox\profiles.ini` (AppData from env `AppData`, else `C:\Users\<user.name>\AppData\Roaming` if it exists).
3. macOS: `~/Library/Application Support/Firefox/profiles.ini`.
4. Linux/UNIX, first existing file of:
   - `~/snap/firefox/common/.mozilla/firefox/profiles.ini` (Ubuntu snap),
   - `~/.config/mozilla/firefox/profiles.ini` (Firefox 147+ XDG layout),
   - else `~/.mozilla/firefox/profiles.ini` (returned even if missing).

**Gap:** Flatpak Firefox (`~/.var/app/org.mozilla.firefox/.mozilla/firefox/profiles.ini`, and
`~/.var/app/org.mozilla.firefox/config/mozilla/firefox/profiles.ini`) is **not** supported by Java. Rust: add these after
the snap entry (improvement; note that a flatpak/snap sandboxed Firefox cannot load AutoFirma's own modules, but AutoFirma
can still read the profile DB). Also consider Firefox ESR/Developer editions on macOS (`/Applications/Firefox*.app`).

#### 3.6.2 `profiles.ini` parsing (`ProfilesIni`)
- Read as UTF-8, line by line, `trim()`. Section headers recognised by prefix (case-insensitive): `[profile…` →
  profile; `[General]` (exact, case-insensitive) → general; `[install…` → install/state. A section ends at an empty line
  or a line starting with `[`.
- Keys compared case-insensitively by prefix; values taken verbatim after the `=`:
  - Profile: `Name=`, `IsRelative=` (`"1"` → true; **default true**), `Path=`, `Default=` (`"1"` → true).
    A profile without `Name` or `Path` is discarded. Absolute path = `IsRelative ? dir(profiles.ini)/Path : Path`.
    `locked` = `<profile>/lock` exists **or** is a symlink (Linux/macOS, dangling symlink allowed) **or** `<profile>/parent.lock` exists (Windows).
  - General: `Version=` (int, **default 1**), `StartWithLastProfile=`.
  - Install: `Default=` (relative profile path, mandatory) and `Locked=` (`"1"`). With several `[Install…]` sections the
    stored one is replaced by a later one **unless** the stored one declared `Locked=`.

#### 3.6.3 Profile selection (`NSPreferences.getFireFoxUserProfileDirectory`)
A profile is **dummy** (invalid) if its directory has fewer than **10** entries, or neither `key4.db` nor `key3.db` is readable.
1. Active profile:
   - `General.Version == 1`: first non-dummy profile that is `locked`.
   - otherwise (Version ≥ 2, modern Firefox): profile whose raw `Path` string equals the `[Install…]` `Default=` value,
     accepted only if non-dummy.
2. Else first non-dummy profile with `Default=1`.
3. Else the non-dummy profile whose directory has the most recent mtime.
4. Else the first profile in file order (even if dummy).
5. Result cached per canonical `profiles.ini` path for the process lifetime.

Failure handling: on Windows any failure → `IOException("No se ha encontrado el directorio de perfil de Mozilla")`;
on other OSes any exception falls back to the **shared NSS directory** (3.6.9). The Windows path is converted to a short
8.3 name with `/` separators (Rust: unnecessary; use the long path).

`isFirefoxAvailable()` (used by preferences UI and default-store validation) = profile dir found **and** NSS lib dir found.

#### 3.6.4 NSS library directory
- **Windows:** read `<profile>/compatibility.ini`, line starting with `LastPlatformDir=` (max 512 lines × 4 KB); value =
  Firefox install dir (e.g. `C:\Program Files\Mozilla Firefox`). Convert to short name. If it contains chars outside
  `:\0-9a-zA-Z-_.~`, copy `softokn3.dll` + dependencies (list below) to a temp dir (`%SystemRoot%\Temp\nss*` if writable,
  else user temp) — Java bug 6581254 workaround, Rust: skip. Verify `softokn3.dll` exists/readable; read its PE machine
  type and if it does not match the process (x86 vs x64) use the **bundled NSS**: resource `/nss/WINDOWS/nss32.zip` or
  `nss64.zip` unzipped (zip-slip protected) to `~/.afirma/nss/<32|64>`. Rust: bundle NSS for each shipped Windows arch
  (x64, arm64) and use it when Firefox's NSS is missing or of another arch.
  Windows dependency preload order: `msvcr100.dll, msvcp100.dll, msvcr120.dll, msvcp120.dll, vcruntime140.dll, msvcp140.dll,
  mozglue.dll, nss3.dll, mozutils.dll, mozcrt19.dll, nspr4.dll, plds4.dll, plc4.dll, nssutil3.dll, mozsqlite3.dll,
  sqlite3.dll, nssdbm3.dll, freebl3.dll` (only those present; done only if the first NSS load fails). Rust: call
  `SetDllDirectoryW(nssDir)`/`AddDllDirectory` before loading `softokn3.dll`/`nss3.dll`.
- **macOS:** first dir containing `libsoftokn3.dylib` among `/Applications/Firefox.app/Contents/MacOS`, `/lib`, `/usr/lib`,
  `/usr/lib/nss`, `/Applications/Minefield.app/Contents/MacOS`. If loading fails Java creates symlinks of
  `libmozglue, libmozutils, libnspr4, libplds4, libplc4, libnssutil3, libmozsqlite3, libnss3` (`.dylib`) into
  `/usr/local/lib` via an **administrator AppleScript** — Rust: **do not** do this; load by absolute path. Gotcha: a
  hardened-runtime, signed Rust binary cannot `dlopen` Firefox's dylibs unless it has the
  `com.apple.security.cs.disable-library-validation` entitlement (or bundle its own NSS).
- **Linux/UNIX:** candidate dirs (kept only if they exist, symlinks resolved), in order:
  `/usr/lib/x86_64-linux-gnu/nss`, `/usr/lib/x86_64-linux-gnu` (64-bit) or `/usr/lib/i386-linux-gnu/nss`,
  `/usr/lib/i386-linux-gnu` (32-bit); `<syslib>/nss`, `<syslib>`, `<syslib>/firefox`, `<syslib>/firefox-<highest numeric version>`,
  `<syslib>/thunderbird`, `/lib64` (or `/lib`), `/opt/firefox`, `/usr/lib64` (or `/usr/lib`), `/opt/firefox-<highest>`,
  `/opt/fedora-ds/clients/lib`, `/opt/google/chrome` — where `<syslib>` = `/usr/lib64` if it exists else `/usr/lib`.
  Pick the first containing `libsoftokn3.so` whose ELF machine matches the process. Then require that one of
  `mozsqlite3.so, libmozsqlite3.so, libsqlite3.so.0, libnspr4.so` can be loaded from **any** candidate dir.
  **Bug:** the ELF arch check only accepts x86/x86-64, so **aarch64 Linux never finds NSS** and the
  `aarch64-linux-gnu` multiarch dir is not in the list. Rust: derive the multiarch triple from the target
  (`x86_64-linux-gnu`, `aarch64-linux-gnu`, `i386-linux-gnu`…) and compare ELF `e_machine` with the build target.
  Unix dependency preload list: `libnspr4.so, libplds4.so, libplc4.so, libnssutil3.so, libsqlite3.so, libmozsqlite3.so, libsqlite3.so.0`.

#### 3.6.5 NSS initialisation string (exact Java config for SunPKCS11)
```
name=NSSCrypto-AFirma\r\n
library=<nssLibDir><fileSeparator><softokn>\n          softokn = softokn3.dll | libsoftokn3.dylib | libsoftokn3.so
attributes=compatibility\n
slot=2\n
showInfo=false\n
allowSingleThreadedModules=true\n
nssArgs="configdir='<profileDir>' certPrefix='' keyPrefix='' flags='readOnly'"
```
- `flags='readOnly'` omitted when `EnableNssWrite` is true (the space before it remains: `keyPrefix='' "`).
- `<profileDir>` is prefixed with `sql:/` when env `NSS_DEFAULT_DB_TYPE == "sql"` **or** `<profileDir>/pkcs11.txt` exists
  (so typically `configdir='sql://home/u/.mozilla/firefox/abcd.default-release'`).
- Load attempts: (1) as is; (2) after preloading dependencies (macOS symlinks); (3) with every `sql:/` removed
  (legacy Berkeley `cert8.db/key3.db`). Failure → `AOException(LOADING_MOZILLA_KEYSTORE_ERROR 201108)`.
- Slot 2 = NSS "internal key storage" slot (user certs and keys of the profile).
- Opening the key store: first `load(null, "")` (no master password). If that fails, ask the store password callback
  (`"Introduzca la contraseña del almacén de claves de Mozilla Firefox."` `AOKeyStore.5` for MOZ_UNI;
  `"Introduzca la contraseña del almacén de claves del sistema."` `AOKeyStore.13` for SHARED_NSS; if no callback,
  `"Contraseña del almacén de Firefox"` `MozillaUnifiedKeyStoreManager.0`). A wrong master password leaves the NSS part
  empty (logged), it does not abort the aggregate.
- The NSS provider is a **process-wide singleton** (`NssKeyStoreManager.nssProvider`), reused unless `forceReset`.

**Rust options:**
- **A (parity):** `dlopen` `softokn3` and call `C_Initialize` with NSS-specific `pReserved` init string
  `configdir='sql:<dir>' certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly` (the `cryptoki` crate does not
  expose `pReserved`; use `cryptoki-sys`/raw FFI). Use slot 2 (or the slot whose token label is
  `NSS Certificate DB`/`Software Security Device`). Then load each external module separately with `cryptoki` (3.6.7).
- **B (recommended improvement):** FFI to `libnss3`: `NSS_Initialize(configdir, "", "", "secmod.db", NSS_INIT_READONLY | NSS_INIT_NOROOTINIT)`;
  NSS then loads every module listed in `pkcs11.txt` itself; list with `PK11_ListCerts(PK11CertListUser)`,
  find keys with `PK11_FindKeyByAnyCert`, sign with `PK11_Sign`/`SGN_*`, PIN via `PK11_SetPasswordFunc`.
  Gotcha: NSS can be initialised only once per process with one configdir (Java has the same limitation; see 8.6
  on Linux store switching). Use `NSS_InitContext` if both Firefox and shared DBs are needed.

#### 3.6.6 Shared NSS DB (`SHARED_NSS`, Linux)
Directory = first of `~/.pki/nssdb`, `~/snap/chromium/current/.pki/nssdb`, `/etc/pki/nssdb` that is a directory
containing at least one file named `key*.db`. None → `FileNotFoundException("No se ha encontrado un directorio de perfil de NSS compartido")`
→ the NSS part is empty but cards/external modules may still load.

#### 3.6.7 External PKCS#11 modules registered in Firefox
1. Module list source: if env `NSS_DEFAULT_DB_TYPE == "sql"` or `<profile>/pkcs11.txt` exists → parse `pkcs11.txt`
   (falls back to `secmod.db` on IO error); else `secmod.db`.
   - **`pkcs11.txt` parser** (max 512 lines × 4 KB): blank line resets the current module. A line starting with
     `library=` (or containing ` library=`) gives the library; if the same line also contains ` name="`, the library is the
     text up to that token (trimmed) and the name is the quoted text. A line starting with `name=` gives the name (rest of
     line, trimmed, quotes kept). When both non-empty → module `(lib, name)`. The internal module (`library=` empty) is
     thereby skipped.
   - **`secmod.db` heuristic parser** (Berkeley DB, read whole file): for every byte offset `i`: `len1 = BE16(i)`,
     `name = bytes[i+2 .. i+2+len1]` stripped up to the last non-printable char (<32 or >126); then
     `len2 = BE16(next)`, `lib = next string`. Accept when `lib` ends with `.dll/.DLL` (Windows) or `.so`, contains `.so.`, or ends
     `.dylib` (non-Windows) **and** the library is found (as given, or in the library path). First occurrence per lib wins.
     Result cached for the process. Rust: port as-is (legacy profiles only).
2. Exclusion: if `excludePreferredModules`, drop libraries matching the native-DNIe list (table 1.4).
3. Windows only: add the *known modules* (table 1.4) not already present (by case-insensitive `endsWith` of lib name).
4. `purgeStoresTable`: de-duplicate by library path (lower-cased if it ends with `.dll`); drop any lib containing `nssckbi`.
5. Map is keyed by **description** (module name); iteration order is a hash order → Rust: keep file order (deterministic).

Loading (`MozillaUnifiedKeyStoreManager.init`), in order:
1. Unless `LoadSscdOnly`: add the NSS internal store (3.6.5); failures are logged, an empty manager is still added.
2. If `forceReset || first init`: `addPreferredKeyStoreManagers` (DNIe → CERES 4.30 → CERES → SmartCafe; 3.7.2).
   If the user cancels the card PIN/CAN: `preferredKsAdded=false`, `excludePreferredKeyStores=true`.
3. If no preferred store was added: get the external modules (`excludePreferredModules = excludePreferredKeyStores`,
   i.e. native DNIe modules are **included** unless the user cancelled the Java driver), then for each module:
   init as PKCS#11 (prompt `"Introduzca la contraseña de <descr>"`); on Linux retry once on failure; cancel → next module;
   **on the first success add it and stop** (only ONE external module is ever loaded).
4. `setKeyStoreType(type)`.

**Quirk:** because of 2–3, when a DNIe/CERES is detected by the Java driver no Firefox external module is loaded at all.
Rust parity: same; improvement: load all modules with tokens present (de-duplicated by thumbprint).

#### 3.6.8 `MOZ_UNI_WITH_OS` (used for browser-invoked operations when MOZ_UNI is requested)
Same as 3.6.7 but after the NSS internal store it adds the OS store: Windows → full `CAPIUnifiedKeyStoreManager`
(`forceReset=true`, includes its own preferred-card probing); macOS → `getMacOSXKeyStoreManager` (also probes cards);
Linux → nothing. Then the Mozilla preferred probing and external modules as above. Failures adding the OS store are logged.

#### 3.6.9 Profile directory fallback
Non-Windows: if `profiles.ini` processing throws, the profile dir becomes the shared NSS dir (3.6.6). If no profile at all
is found the result may be null (Java then builds a broken config) → Rust: treat as "Firefox not available".

#### 3.6.10 Caching quirks (decide per mode)
- The factory caches **one** Mozilla aggregate in a static shared by `MOZ_UNI` and `MOZ_UNI_WITH_OS`; `forceReset` does
  **not** bypass it; it is not cached if it contains a DNIe-Java sub-store. Consequence: the first one requested wins for
  the process lifetime. Rust: cache per store id and honour `forceReset` (fix).
- **Bug:** the factory initialises every Mozilla aggregate with type `SHARED_NSS` (the class's own type is overwritten
  by `init(SHARED_NSS…)`), so a loaded `MOZ_UNI` reports `SHARED_NSS` until refreshed: dialog title says `"NSS"` and on
  Linux the store switcher offers "system" (8.6). Rust: report the real type.

#### 3.6.11 `SHARED_NSS` external modules quirk
`SharedNssKeyStoreManager` overrides only the no-arg `getExternalStores()`, which is never called; the inherited
`getExternalStores(boolean)` reads the **Firefox profile's** `pkcs11.txt` (or the shared dir only if no Firefox profile).
`IncludeNativeDniePkcs11` therefore has no effect. Rust: for `SHARED_NSS` read `<sharedDir>/pkcs11.txt` (fix) but
document the change; keep a parity flag if needed.

#### 3.6.12 Linux early preload
On Linux (non-Windows/non-macOS) the local app (not protocol) pre-loads `MOZ_UNI` at startup with description
`"AFIRMA-NSS-KEYSTORE"` and no password callback, because SunPKCS11/NSS fails with `CKR_DEVICE_ERROR` if initialised later.
Rust: not required (no SunPKCS11), but initialise NSS once and early if option B is used.

### 3.7 DNIe, CERES and other cards through the built-in driver (jmulticard)

#### 3.7.1 What jmulticard provides (external library `es.gob.afirma.jmulticard:jmulticard` 2.1)
- PC/SC access (`javax.smartcardio`), card detection, DNIe 3.0/4.0 (contact: CWA-14890 secure channel; contactless: PACE
  with **CAN**), FNMT CERES (≤4.x and 4.30+, also "TIF" cards), G&D SmartCafe PKCS#15.
- JCA provider exposing a `KeyStore` (`DNI`, `CERES`, `CERES430`, `GDSCPKCS15`) and RSA `Signature`s.
- DNIe aliases: `CertAutenticacion`, `CertFirmaDigital` (friendly names = CN, e.g. `"APELLIDO1 APELLIDO2, NOMBRE (AUTENTICACIÓN)"`
  / `"… (FIRMA)"`).
- PIN is requested **at signing time**, not at load (store and entry password callbacks are null); the card driver calls
  back into AutoFirma's handler with JAAS callbacks:
  - `PasswordCallback` (or jmulticard `CardWithRetriesPasswordCallback` exposing `getRetriesLeft()`) → PIN,
  - `CustomAuthorizeCallback` → "confirm signature" (DNIe only),
  - `TextInputCallback` / `es.gob.jmulticard.callback.CustomTextInputCallback` → **CAN** for contactless DNIe.
- Exceptions used by AutoFirma (by class name): `es.gob.jmulticard.apdu.connection.CardNotPresentException`,
  `es.gob.jmulticard.card.InvalidCardException`, `es.gob.jmulticard.card.dnie.BurnedDnieCardException`,
  `es.gob.jmulticard.CancelledOperationException`, `es.gob.jmulticard.jse.provider.BadPasswordProviderException`,
  `es.gob.jmulticard.jse.provider.SignatureAuthException` with cause `es.gob.jmulticard.card.BadPinException` (wrong PIN)
  or `es.gob.jmulticard.card.AuthenticationModeLockedException` (blocked).

**Rust:** this is the largest piece of work. Options:
1. Port the needed parts of jmulticard on top of the `pcsc` crate: DNIe 3/4 secure messaging (ICC/IFD certificate
   exchange, CWA-14890 SM with 3DES/AES), PACE-CAN for NFC, PIN verify with retries (SW `63Cx`), PKCS#1 v1.5 signature via
   the card (DigestInfo built by host), file system reading of certificates (compressed with zlib on DNIe).
   CERES 4.30+ uses the same DNIe-like command set ("allowAnotherCards"); older CERES uses a PKCS#15 profile.
2. Interim: rely on OpenSC (`opensc-pkcs11`), which supports DNIe (`dnie` driver) and many CERES cards, through the
   generic PKCS#11 backend, keeping the same UI (PIN dialog, confirmation) via `CKF_PROTECTED_AUTHENTICATION_PATH` absent.
The rest of this section specifies the behaviour to keep regardless of the transport.

#### 3.7.2 Preferred-store probing (`KeyStoreUtilities.addPreferredKeyStoreManagers(aggregate, parent)`)
Executed when opening `WINDOWS`, `APPLE`, `MOZ_UNI`, `MOZ_UNI_WITH_OS`, `SHARED_NSS`, `KNOWN_SMARTCARDS`:
1. Unless DNIe driver disabled (1.5): try to open `DNIEJAVA`; success → add as preferred, **return true** (stop).
2. Unless CERES driver disabled: try `CERES_430`; success → add, return true. Then try `CERES`; success → add, return true.
3. Only if SmartCafe enabled: try `SMARTCAFE`; success → add, return true.
4. Return false.
Any failure (no reader, no card, other card) is logged and the next candidate is tried; **cancellation propagates**
(`AOCancelledOperationException`) and the caller treats it as described in 3.1/3.6.7. Every successful card store is
`preferred=true` → duplicates elsewhere are hidden (section 2).

Gotcha: probing touches the reader on every store load (start-up latency; on Windows it breaks the minidriver session,
hence the CAPI refresh in 3.1.1). With `MOZ_UNI_WITH_OS` the card is probed twice (once inside the OS store, once by the
Mozilla aggregate). Rust: probe once per aggregate build and reuse the result.

#### 3.7.3 Direct DNIe store (`DNIEJAVA`) from the local GUI start screen
`SimpleKeyStoreManager.getKeyStore(dnie=true, forced, parent)`:
- `CardNotPresentException` → confirm `"No se ha detectado un DNIe insertado ¿Desea reintentar?"`
  (title `"No hay tarjeta en el lector"`) → Yes = retry.
- `InvalidCardException` → confirm `"La tarjeta detectada en el lector no es un DNIe.\n¿Desea reintentar?"`
  (title `"Detectada tarjeta incorrecta"`) → Yes = retry.
- `BurnedDnieCardException` → warning `"Su DNIe está dañado, debe acudir a una comisaría de policía para renovarlo.\nSe continuará con el almacén por defecto del sistema."` (title `"Detectado DNIe dañado"`).
- (dead code) `SmartCardLockedException` → `"Su DNIe está bloqueado, debe acudir a una comisaría de policía para desbloquearlo.\nSe continuará con el almacén por defecto del sistema."` (title `"Detectado DNIe bloqueado"`).
- other → error `"No ha sido posible inicializar su DNIe.\nSe continuará con el almacén por defecto del sistema."`
  (title `"Error en la iniciaizaci\u00F3n del DNIe"` — sic).
- The exception class is taken from the **third-level cause** (`e.getCause().getCause().getCause()`).
- If `forced` and the DNIe could not be loaded → `NoDnieFoundException` (no store set); else continue with the default store.
The start screen itself (`DNIeWaitPanel`) is shown only when the preference `hideDnieStartScreen` is false, no file was
pre-selected and PC/SC lists at least one reader.

#### 3.7.4 PIN, CAN and confirmation dialogs (jmulticard UI module)
Handlers: DNIe → `DnieCacheCallbackHandler`; CERES/CERES 4.30 → `SmartcardCacheCallbackHandler`; SmartCafe →
`SmartcardCallbackHandler` (no cache). Dialog owner = the parent passed to the store (static, last one wins).

**PIN dialog** (`InputPasswordSmartcardDialog`, modal, accessible):
- Title: DNIe `"DNI Electrónico: Introducción de PIN"` (`CommonPasswordCallback.1`); other cards
  `"Tarjeta inteligente: Introducción de PIN"` (`.2`).
- Icon: `/images/dnie.png` (DNIe) or `/images/chipcard.png`.
- Message: DNIe `"Por favor, introduzca el PIN del DNIe."` (`.4`) or with retries
  `"Por favor, introduzca el PIN del DNIe.\nIntentos restantes: %0"` (`.3`); cards `"Por favor, introduzca el PIN de la tarjeta."`
  (`.6`) / `"…\nIntentos restantes: %0"` (`.5`). (SmartCafe uses the driver's own prompt text.)
  Mnemonic `P` focuses the field.
- Secure field: max **20** chars typed, echoed as `*`, Ctrl+V / Shift+Insert / context menu `"Pegar texto"` paste,
  Backspace deletes last char; eye button `"Mostrar u ocultar contraseña"` (tooltips `"Mostrar contraseña"`/`"Ocultar contraseña"`)
  toggles visibility, shortcut **Ctrl+P**.
- Checkbox (DNIe and CERES only) `"Recordar contraseña durante la sesión"` (`InputPasswordSmartcardDialog.useCache`),
  mnemonic `e`; initial state = persisted preference (below).
- Buttons `"Aceptar"` (Alt+A) — enabled only when **4 ≤ length ≤ 16** — and `"Cancelar"` (Alt+C). Enter submits when valid;
  Esc cancels. Cancel → `CancelledOperationException`.
- Headless (`java.awt.headless`): console prompt `"<prompt>:\n"` with no echo; PIN length must be 8–16 or
  `"Longitud del PIN incorrecta"` and re-ask; no console → error.

**Signature confirmation** (DNIe only, `CustomAuthorizeCallback`): modal Yes/No `"Sí"`/`"No"`, title
`"DNI Electrónico: Firma electrónica"`, text `"¿Desea realizar una firma electrónica con su clave privada?"`, icon `dnie.png`.
Console fallback accepts `si, s, sí, y, yes` / `no, n`. **Quirk:** in headless mode no dialog is shown and authorisation stays false.

**CAN dialog** (contactless DNIe): `JOptionPane` OK/Cancel, title `"DNI Electrónico: Introducción de CAN"`
(`CanPasswordCallback.2`), label `"Por favor, introduzca el CAN del DNIe"` (`.0`), password field (10 cols), image
`/images/can_example.png` scaled to 230×140 with a light-grey 5px border, dialog 350×310, application-modal.
Closing the window returns an **empty CAN** (not cancel); Cancel → `CancelledOperationException`. CAN is never cached by
AutoFirma (jmulticard may cache it internally per card).

#### 3.7.5 PIN cache
- Per handler instance (one per opened card store): when "Recordar contraseña durante la sesión" is ticked the PIN is
  stored in memory and reused for subsequent PIN callbacks without showing the dialog; for DNIe the **confirmation answer is
  cached too** (`confirmed` flag) — once confirmed, later signatures are not re-confirmed while the cache lives.
- Expiry: a timer of **3600 s** is started at the **first PIN request** (not at last use) and then clears PIN and confirmation.
  It is not restarted on later use. Refreshing/re-opening the store creates a new handler (cache lost).
- The checkbox state is persisted when changed: Java Preferences node of package `es.gob.afirma.keystores.jmulticard.ui`
  (`/es/gob/afirma/keystores/jmulticard/ui`), keys `useCacheDni` (DNIe) and `useCacheCeres` (CERES), default `false`.
- Preference `jmulticardCachePassword` (default `false`) exists in `preferences.properties` but is **unused**.
- Rust: store PIN in a zeroizing buffer; expiry absolute 1 h from first entry (parity); also clear on card removal (improvement).

#### 3.7.6 Wrong PIN / blocked card while signing
Signers translate driver errors (see 5.3): wrong PIN → `PinException` (`INVALID_SMARTCARD_PIN` 501003); blocked →
`LockedKeyStoreException` (`SMARTCARD_LOCKED` 511004); cancelled in driver dialog → `AOCancelledSMOperationException`.
Recovery flows are in 5.4.

### 3.8 Windows temporary profile: known smart cards (`KNOWN_SMARTCARDS`)
`SmartCardUnifiedKeyStoreManager.init`: probe preferred cards (3.7.2; cancel → skip preferred-type modules, i.e. FNMT-CERES).
If none: for each known card (table 1.4 order FNMT-CERES, CardOS, TUI, SafeSign) try each library path: init PKCS#11 with
prompt `"Por favor, introduzca la contraseña de la tarjeta <name>"` (`SmartCardUnifiedKeyStoreManager.0`); cancel → next
library; error → (Linux only) retry once, then next; first success → add and **stop** (only one card).

### 3.9 User/system registered smart cards (preferences)
- Registry = Java Preferences. User node `/es/gob/afirma/core/keystores`; children named `"1"`, `"2"`, … each holding **one**
  key = card name, value = PKCS#11 library path. System node: if user node `/es/gob/afirma/core/systemkeystores` exists **and**
  system pref `/es/gob/afirma/standalone/ui/internalpreferences/allowUpdateConfig` is true → that node; else system root
  `/es/gob/afirma/core/keystores` if it exists; else none.
- Adding (`addSmartCardToUserRec`) uses the first free numeric child. Names made unique with `-1`, `-2`… when imported
  (`checkCorrectName`); imported user cards whose library is already registered are skipped.
- A registered card name resolves to store `PKCS11` with that name (9.1). In the selection dialog's store menu every user
  card and then every system card appears as an item that opens the card's library (8.4).

---

## 4. Aliases, friendly names, chains and private keys

### 4.1 Candidate list construction (`KeyStoreUtilities.getAliasesByFriendlyName`)
Input: aggregate alias list, `checkPrivateKeys`, `showExpiredCertificates`, filters. Steps, per alias:
1. `getCertificate(alias)`; driver cancellation / jmulticard `BadPasswordProviderException` → **abort** (propagate);
   other runtime error or null → skip alias.
2. If `!showExpiredCertificates` and `now ∉ [notBefore, notAfter]` → drop.
3. If `checkPrivateKeys` and `!isKeyEntry(alias)` (or it throws) → drop. (All AutoFirma flows pass `true`.)
4. Apply filters (section 7) – union over the filter list.
5. Friendly name = `getCN(cert)`: value of the first `CN=` in the subject string (Java `X500Principal.toString()` format,
   Appendix A), else first `OU=`, else the value of the first attribute; quoted values are unquoted; if the certificate has no
   usable subject → `alias.trim()` (CERES aliases end with `\r`).
Rust: build `Vec<Candidate { backend, alias, cert, chain, friendly_name }>`.

### 4.2 De-duplication summary

| Mechanism | Where |
|---|---|
| SHA-1 thumbprint deactivation of entries also present in a preferred card store | `AggregatedKeyStoreManager.addKeyStoreManager` |
| Same serial number → keep first | macOS keychain only |
| Unique alias suffixes | SunMSCAPI (`" (n)"`), Java<9 workaround (`" - hash"`) |
| Same library path / `nssckbi` | Firefox module list |

Not de-duplicated: the same certificate in NSS internal DB and an external module, or in two backends without a preferred
card. Rust improvement: de-duplicate all backends by thumbprint, preferring the backend that has the private key, then the
hardware-backed one.

### 4.3 Chains
The chain is what the backend returns (CAPI chain engine, SunPKCS11 builds it from certificates present on the token by
issuer/subject, PKCS#12 bag order, keychain `SecTrust`-built chain, jmulticard returns the card certificates). AutoFirma does
not complete chains from AIA. `NameCertificateBean.getCertificate()` = `chain[0]`; entries with an empty/null chain break the
dialog (**bug**, 8.9) — Rust: fall back to `[cert]`.

### 4.4 Selected entry
`CertificateContext(keyStoreManager, alias)` is returned by the dialog; callers then call
`keyStoreManager.getKeyEntry(alias)`. The key store manager may be a **different** store than the one requested, because the
user can switch store inside the dialog; protocol callers must use the context's manager (they do).

---

## 5. Signing operation

### 5.1 Algorithm naming
`composeSignatureAlgorithmName(algorithm, keyType)`: digest part from the requested algorithm with `-` removed
(`SHA-256`→`SHA256`), suffix by key algorithm: `RSA` → `withRSA`, `DSA` → `withDSA`, `EC*` → `withECDSA`, else error
`"Tipo de clave de firma no soportado"`. Supported: `SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA,
SHA1withECDSA, SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA` (+ `SHA1withDSA` legacy).
No RSASSA-PSS. Raw `NONEwith*` constants exist but are unused.

### 5.2 PKCS#1 signer contract (`AOPkcs1Signer.sign(data, algorithm, key, chain, extraParams)`)
1. Signature = `Signature.getInstance("<HASH>with<RSA|ECDSA>")` over the **data bytes** (the caller passes the encoded
   signed attributes / triphase pre-sign data). Optional extraParam `Provider.<keyClassName>` forces a JCA provider (ignore in Rust).
2. Backend computes: RSA = EMSA-PKCS1-v1_5 (DigestInfo + padding, Appendix B); ECDSA = DER `SEQUENCE{r,s}`.
3. **Mandatory verification** (ETSI TS 119 102-1): if a chain is given, verify the signature with `chain[0]` public key;
   mismatch → `AOException("El PKCS#1 de firma obtenido no se genero con el certificado indicado", INVALID_PKCS1_VALUE)`;
   verification error → `VERIFING_PKCS1_ERROR`. Rust must keep this check for all backends.
4. Error mapping: unsupported algorithm → `UNSUPPORTED_SIGNATURE_ALGORITHM`; `initSign` failure → `INVALID_SIGNING_KEY`;
   other → `SIGNING_PKCS1_ERROR`; card cancellations/PIN errors as 5.3.

### 5.3 Per-backend signing and error translation

| Backend | Who hashes | Primitive | Output | PIN/cancel/locked mapping |
|---|---|---|---|---|
| Windows CNG | host | `NCryptSignHash` + `BCRYPT_PAD_PKCS1` | RSA: big-endian; EC: `r‖s` → DER | KSP UI; `SCARD_W_WRONG_CHV`→PinIncorrect, `SCARD_W_CHV_BLOCKED`→Locked, `SCARD_W_CANCELLED_BY_USER`→Cancelled |
| Windows CAPI | CSP (`CryptCreateHash`+`HP_HASHVAL`) | `CryptSignHash` | little-endian → reverse | CSP UI; `NTE_BAD_KEY_STATE`/`SCARD_W_*` mapped as above |
| macOS | Security.framework | `SecKeyCreateSignature` (…Message… algorithms) | RSA raw; EC DER | `errSecUserCanceled`→Cancelled, `errSecAuthFailed`→PinIncorrect |
| PKCS#11 / NSS | token (`CKM_SHAxxx_RSA_PKCS`) or host (`CKM_RSA_PKCS` + DigestInfo; `CKM_ECDSA` + hash) | `C_Sign` | RSA raw; EC `r‖s`→DER | `CKR_PIN_INCORRECT`→PinIncorrect, `CKR_PIN_LOCKED`→Locked, `CKR_FUNCTION_CANCELED`→Cancelled, `CKR_USER_NOT_LOGGED_IN`→re-login |
| PKCS#12 | host | software | — | n/a |
| DNIe/CERES (built-in) | host (DigestInfo) | card RSA (INTERNAL AUTHENTICATE / PSO CDS) | RSA raw | `BadPinException`→`PinException` 501003; `AuthenticationModeLockedException`→`LockedKeyStoreException` 511004; `CancelledOperationException`→`AOCancelledSMOperationException`; other auth error → `AuthenticationException` |

Java exception names to keep as Rust error variants: `PinException` (code 501003 "El PIN del la tarjeta inteligente es
incorrecto"), `LockedKeyStoreException` (511004 SMARTCARD_LOCKED, or 511003 KEYSTORE_LOCKED), `AOCancelledSMOperationException`
(user cancelled the smart-card dialog), `AOCancelledOperationException` (500001).

### 5.4 Recovery flows after a signing error
- **Protocol** (`ProtocolInvocationLauncherSign/SignAndSave`): `PinException` → retry the whole "select + sign" with filter
  `EncodedCertificateFilter(<same cert>)` and `mandatoryCertificate=true` (auto-selects the same certificate, store reloaded
  or taken from the preload task), so the PIN dialog shows again with fewer retries. `LockedKeyStoreException` → clear the
  sticky key, error SAF_52 `"El almacen de claves esta bloqueado"`.
- **Local GUI** (`SignPanelSignTask`): `AOCancelledSMOperationException` → refresh store, stop. `PinException` → refresh store
  ("evitar que el driver JMulticard quede en mal estado"), re-select the same certificate via `EncodedCertificateFilter`
  with `mandatory=true`, re-run. `LockedKeyStoreException` → refresh store + error.

### 5.5 Sticky signatory (protocol)
URL params `sticky=true` and `resetsticky=true` (`Boolean.parseBoolean`). If `sticky && !resetsticky` and a key was kept from a
previous operation in the same process, it is reused **without opening any store or dialog**. After selection the key is kept
if `sticky` else cleared; cleared on locked-store errors. (Details belong to the protocol spec; the store layer must allow
holding a `PrivateKeyEntry` handle across operations — keep PKCS#11 sessions/CNG handles alive.)

---

## 6. Password / PIN prompt catalogue

| Situation | Text (es_ES, key) | Implementation | Cached? |
|---|---|---|---|
| PKCS#12 store password | `"Introduzca la contraseña del almacén <file>."` (`AOKeyStore.15`) or `"Introduzca la contraseña del almacén PKCS#12."` (`.1`) | generic password dialog (title `"Introduzca la contraseña"` `JSEUIManager.24`, OK `"Aceptar"`, Cancel `"Cancelar"`) | in memory for that store instance |
| PKCS#12 key password (if differs) | `"Introduzca la contraseña del certificado dentro del fichero PKCS#12."` (`.0`) | same | no |
| Generic PKCS#11 login (at open) | `"Introduzca la contraseña del almacén PKCS#11."` | same | session kept per library (process) |
| Firefox external module login | `"Introduzca la contraseña de <descr>"` | same | session kept |
| Windows temp-profile cards | `"Por favor, introduzca la contraseña de la tarjeta <name>"` | same | session kept |
| Firefox master password | `"Introduzca la contraseña del almacén de claves de Mozilla Firefox."` (`.5`) / `"Contraseña del almacén de Firefox"` | same | NSS session |
| Shared NSS password | `"Introduzca la contraseña del almacén de claves del sistema."` (`.13`) | same | NSS session |
| JKS/JCEKS | `.2`/`.3`, `.6`–`.9` ("…almacén Java.") | same | — |
| Windows smart card | native CSP/KSP dialog | OS | OS policy |
| macOS keychain/token | native | OS | OS |
| DNIe PIN / confirmation / CAN | 3.7.4 | custom dialogs | 1 h optional cache |
| CERES PIN | 3.7.4 | custom | 1 h optional cache |
| CLI | `-password` value used as store password **and** entry password (`CachePasswordCallback`); without it entry password `"dummy"` | none | — |

Generic password dialog details (JSE): label + `JPasswordField(10)`, `QUESTION_MESSAGE`, initial focus in field, closing or
Cancel → `AOCancelledOperationException`.

**Card removal and timeouts.** AutoFirma has no reader monitoring: a removed card manifests as an error on next use
(CAPI/PKCS#11 errors, jmulticard `CardNotPresentException`), the user presses **Recargar/F5** in the dialog to refresh.
No operation timeouts are applied to stores; only the 1 h PIN cache timer. Protocol mode preloads the default store in a
background thread at start-up (9.2). Rust improvement: watch `SCardGetStatusChange` while the dialog is open to auto-refresh,
and drop cached PINs/sessions on removal.

---

## 7. Certificate filters

### 7.1 Where filters come from

| Flow | Source | Default when nothing given |
|---|---|---|
| Protocol operations (`sign`, `cosign`, `countersign`, `signandsave`, `batch`, `selectcert`) | operation **extraParams** (`properties` param, Java `Properties` text): keys `filter`, `filters`, `filters.1..N`, plus `headless`, `mandatoryCertSelection` | `[ExpiredCertificateFilter(hide expired)]` |
| CLI `-certgui` | `-config` extraParams + `-filter` value stored as `filters` | same default |
| CLI `-filter` without GUI | value stored as `filters` → first filter only | none (no expiry/key checks) |
| Local GUI sign (`SignPanel.getCertFilters`) | preferences (7.6) | expiry handled by `showExpiredCerts` pref |
| Preferences "Ver contenido" | same preference filters | same |

### 7.2 Configuration keys and combination (`CertFilterManager`)
- Exactly one of (precedence order): `filter`; else `filters`; else `filters.1`, `filters.2`, … (contiguous; stops at first gap).
- Each value is a **filter expression**. Expressions from `filters.N` are combined with **OR** (union); items inside one
  expression (separated by `;`) are combined with **AND**.
- OR evaluation detail (`getAliasesByFriendlyName`): expressions are applied in order on the aliases **not yet accepted** by
  previous expressions; accepted aliases are moved to the result. This matters for alias-level filters (`ssl`, `qualified`,
  `pseudonym`) whose pairing searches only the remaining aliases.
- AND evaluation detail: the items of an expression are **sorted alphabetically (case-sensitive `String` order)** first, then
  applied sequentially, each receiving the aliases surviving the previous ones (`MultipleCertificateFilter`).
- If the resulting filter list is empty (no key present) → default `ExpiredCertificateFilter(false)`. If any key is present the
  default is **not** added — e.g. `filters=keyusage.nonrepudiation:true` shows expired certificates (gotcha; the protocol dialog
  is created with `showExpiredCertificates=true`).
- Unknown items are logged (`"Se omitira el filtro '<f>' por no estar reconocido"`) and ignored; an expression whose items are all
  ignored becomes an empty AND = **accept everything**.
- `mandatoryCertificate` (auto-select a single match) = `headless == "true"` (case-insensitive parse) **or**
  `mandatoryCertSelection` equals `"false"` (case-insensitive).
- `allowExternalStores` = false if any item equals `disableopeningexternalstores`.

### 7.3 Grammar
```
expression   = item *( ";" item )                       ; no escaping: values cannot contain ";"
item         = keyword-item / "disableopeningexternalstores"
keyword-item = prefix value                              ; prefix matched case-insensitively with startsWith
prefix       = "dnie:" / "ssl:" / "qualified:" / "signingcert:" / "authcert:" / "sscd:" / "nonexpired:"
             / "subject.rfc2254:" / "subject.contains:" / "issuer.rfc2254:" / "issuer.rfc2254.recurse:"
             / "issuer.contains:" / "thumbprint:" / "policyid:" / "pseudonym:" / "encodedcert:"
             / "keyusage." ku-name ":"
ku-name      = "digitalsignature" / "nonrepudiation" / "keyencipherment" / "dataencipherment" / "keyagreement"
             / "keycertsign" / "crlsign" / "encipheronly" / "decipheronly"
```
The colon is part of the prefix: `signingcert` without `:` is unknown. Values keep their case. Matching order of the
`if/else` chain matters only for prefixes sharing a stem: `issuer.rfc2254.recurse:` is distinct because the character after
`rfc2254` is `.` not `:`.

### 7.4 Filter semantics

| Item | Semantics (exact) |
|---|---|
| `dnie:` (value ignored) | `SignatureDNIeFilter`: issuer matches LDAP filter `(&(cn=AC DNIE *)(ou=DNIE)(o=DIRECCION GENERAL DE LA POLICIA)(c=ES))` **and** KeyUsage `nonRepudiation=true` (others don't care). I.e. only DNIe **signing** certificates. |
| `signingcert:` | `NOT AuthenticationDNIeFilter` where AuthenticationDNIe = same DNIe issuer filter **and** `digitalSignature=true`. Hides the DNIe authentication cert; everything else passes. |
| `authcert:` | `NOT SignatureDNIeFilter`. Hides the DNIe signing cert. |
| `ssl:<hexSerial>` | Normalise: trim, remove spaces and `#`, strip leading `0`s; cert serial = hex of the two's-complement big-endian bytes (uppercase), same normalisation; compare case-insensitively. If the matching cert is a DNIe **authentication** cert, return instead the alias of another cert (≠ same position) that is a DNIe **signing** cert with the same subject `serialNumber` attribute (2.5.4.5, compared as the RFC 2253 hex-DER form, case-insensitive) and the same `notAfter` date formatted `yyyy-MM-dd` in local time zone; if none, nothing. Non-DNIe-auth matches are returned as is. |
| `qualified:<hexSerial>` | Same serial matching. If the matching cert is a "signature cert" (KeyUsage pattern: default `nonRepudiation=true`; for issuer string exactly `C=ES, O=Generalitat Valenciana, OU=PKIGVA, CN=ACCV-CA2` the pattern is `digitalSignature=true` and bits 1–7 false) → return it. Else look among the candidate aliases for a different-serial cert that is a signature cert with the same issuer DN, same subject serialNumber and same `notAfter` (`yyyy-MM-dd`, `Locale.US`, local TZ) → return that one. Else return the original cert **unless** it is a DNIe authentication cert. Certificates without KeyUsage are never "signature certs". |
| `nonexpired:` | `nonexpired:` alone → hide expired/not-yet-valid. `nonexpired:<v>` → hide iff `v` parses as `true` (case-insensitive); any other value shows all. |
| `sscd:` | Certificate has extension `1.3.6.1.5.5.7.1.3` (QCStatements) containing statement id `0.4.0.1862.1.4` (QcSSCD). Parse errors → no match. |
| `keyusage.<name>:<true\|false\|null>` | All `keyusage.*` items of an expression form one 9-position pattern (order: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly). `null` = don't care; any value other than `true`/`null` (case-insensitive) means **false** (e.g. `yes` → false). Match iff every non-null position equals the cert bit. **A certificate without KeyUsage extension never matches**, even with an all-null pattern. |
| `subject.rfc2254:<ldap>` / `issuer.rfc2254:<ldap>` | RFC 2254 search filter evaluated over the subject/issuer DN attributes (7.5). Empty value → construction error (operation fails). |
| `issuer.rfc2254.recurse:<ldap>` | Match iff **any** certificate of the chain (including the end-entity itself) has a **subject** matching the filter. |
| `subject.contains:<text>` / `issuer.contains:<text>` | Case-insensitive substring on the Java `X500Principal.toString()` string (Appendix A), e.g. `issuer.contains:O=FNMT` or `subject.contains:12345678Z`. Empty text matches all. |
| `thumbprint:<alg>:<hex>` | Exactly two `:`-separated params after the prefix, else the item is silently ignored. Digest of DER with `<alg>` (Java names: `SHA1`, `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`, `MD5`…; unknown → no match); compare to `<hex>` with spaces removed, case-insensitive. |
| `policyid:<oid>[,<oid>…]` | Cert must have a CertificatePolicies extension and **every** policy OID of the cert must be in the list (subset semantics; a cert with an extra policy is rejected). Empty value → ignored. |
| `pseudonym:` / `pseudonym:andothers` (default) | A cert is "pseudonym" if its subject (RFC 2253) contains attribute `2.5.4.65`. If no pseudonym certs in the candidate set → all pass. Otherwise remove each non-pseudonym cert that has a pseudonym "twin": same issuer DN, identical KeyUsage arrays, and `|notAfter difference| < 60 s`; return pseudonym certs + remaining others. |
| `pseudonym:only` | Only pseudonym certs (possibly none). Any other value (except `andothers` case-insensitively → andothers) behaves as `andothers`. |
| `encodedcert:<base64>` | Exact string equality with the standard Base64 (with padding, no line breaks) of the certificate DER. Used internally for PIN-retry re-selection. |
| `disableopeningexternalstores` | Not a filter; hides the "change store" button in the dialog. |

### 7.5 RFC 2254 evaluation (`RFC2254CertificateFilter` + `SearchFilter`)
- DN source: Java `getSubjectDN().toString()` / `getIssuerDN().toString()` (Appendix A format) parsed as an LDAP name; build an
  attribute map **type → value** with case-insensitive types; if a type repeats, the value of the **left-most** occurrence in the
  string wins (only one value per type). Types are Java keywords (`CN, C, L, ST, O, OU, T, STREET, DC, UID, SERIALNUMBER,
  EMAILADDRESS, GIVENNAME, SURNAME, INITIALS, GENERATION, DNQ, IP`) or `OID.<dotted>` for others. Non-string (hex `#…`)
  values never match.
- Filter syntax: if it does not start with `(` it is wrapped in parentheses (so `cn=Juan*` is valid). Supports `&`, `|`, `!`,
  `=` (with `*` wildcards), `~=` (same as `=`), `>=`, `<=` (lexicographic, case-sensitive `compareTo`), presence `attr=*`.
  `:=` extensible match → parse error. Values: everything up to the next `)`; no `\XX` escape decoding; trimmed.
- Equality: `*` alone → true; no `*` → case-insensitive equality; with `*` → case-insensitive ordered substring match.
  **Quirk:** when the pattern does not start with `*`, the first chunk is checked with `startsWith` but the search for the
  following chunks restarts at position 0 (e.g. `ab*b` matches `ab`). Reproduce for parity.
- Missing attribute → false. Empty DN → false (cert hidden).
- **Fail-open:** any parse or evaluation error → the certificate **passes** (is not removed).

### 7.6 Local GUI preference filters (`SignPanel.getCertFilters`, also "Ver contenido")
AND-combined (in this order) when enabled:
1. `useOnlySignatureCertificates` (default `false`) → `KeyUsageFilter(nonRepudiation=true)`.
2. `skipAuthCertDnie` (default **`true`**) → `SkipAuthDNIeFilter` (= NOT AuthenticationDNIe).
3. `useOnlyAliasCertificates` (default `false`) → `PseudonymFilter("only")` (note: shows **only** pseudonym certs, possibly none,
   despite the label "Usar exclusivamente certificados de seudónimo").
Plus `showExpiredCerts` (default `false`) controls expired certificate visibility.
These preferences do **not** apply to protocol/CLI flows: by default the browser flow shows both DNIe certificates.

### 7.7 Examples
```
filters=nonexpired:;keyusage.nonrepudiation:true            # valid certs with non-repudiation
filters=issuer.rfc2254:(|(o=FNMT-RCM)(o=DIRECCION GENERAL DE LA POLICIA))
filters.1=dnie:                                              # DNIe signing cert ...
filters.2=issuer.contains:O=FNMT-RCM;nonexpired:             # ... OR any valid FNMT cert
filter=thumbprint:SHA-256:3F2A…;disableopeningexternalstores
filters=qualified:0123ABCD                                   # cert with that serial, or its signing twin
filters=policyid:2.16.724.1.2.2.2.3,1.3.6.1.4.1.5734.3.10.1
headless=true                                                # auto-select if exactly one candidate
mandatoryCertSelection=false                                 # same effect
```

---

## 8. Certificate selection dialog

### 8.1 Entry flow (`AOKeyStoreDialog.show()`)
1. Compute candidates (4.1) → `NameCertificateBean[]` (alias, friendly name, chain).
2. If `mandatoryCertificate` and **exactly one** candidate → return it without any UI.
3. Else show the dialog. Result: OK with a selection → alias; Cancel/close → `AOCancelledOperationException("No se ha seleccionado certificado")`;
   if the list was **empty when the dialog closed** (whatever button) → `AOCertificatesNotFoundException` → protocol error
   SAF_19 `"No hay ningun certificado válido en su almacén. Compruebe las fechas de caducidad e instale un certificado válido."`
   (codes 501001/502001/504001), local GUI `"El almacén no contiene ningún certificado que se pueda usar para firmar."`.
4. `checkValidity` warnings (`AOKeyStoreDialog.getKeyEntry`) exist (`"Puede que el certificado haya caducado.…¿Desea continuar con la operación?"`
   `AOKeyStoreDialog.2/.3/.4`, title `"Advertencia"`) but **no AutoFirma flow calls it** → never shown. Rust: optional.

### 8.2 Window
- Modal `JOptionPane` dialog, `alwaysOnTop=true` (set false while a sub-dialog — PIN, file chooser — may appear after refresh /
  store change), white background, height clamped to screen height.
- Title: `"Diálogo de seguridad del almacén <storeName>"` (`CertificateSelectionDialog.0`, storeName = display name of the first
  sub-store type); if a library/file name is known append `" : <file name>"` (e.g. `" : opensc-pkcs11.so"`). After a store change
  the title is reset **without** the library suffix.
- Buttons: `"Aceptar"` / `"Cancelar"` (OK/Cancel). In "view only" mode (preferences "Ver contenido") only `"Aceptar"`.
- Initial focus: the certificate list when >1 certificate; otherwise default (OK button).

### 8.3 Layout (top to bottom)
1. Header row: headline `"Seleccione un certificado"` (`CertificateSelectionPanel.0`), Verdana bold 14 px, colour `#0033BC`
   (white in high contrast); then toolbar icons (18 px, hand cursor, tooltips/accessible names):
   - Refresh `ic_autorenew` — `"Recargar la lista de certificados"` (`UtilToolBar.1`);
   - Change store drop-down `ic_open_in_browser` — `"Cambiar almacén de claves"` (`UtilToolBar.2`), only if external stores
     allowed and the available list is non-empty;
   - Help `ic_help` — `"Ayuda"` (`UtilToolBar.3`) opens `helpUrl` from `/resources/selectiondialogutil.properties`
     = `https://github.com/ctt-gob-es/clienteafirma/wiki/Help-desktop-select-certs` + `"-" + <language>-<COUNTRY>` (e.g. `…-es-ES`);
   - Views drop-down `ic_view_arrow` — `"Vistas de certificados"` (`UtilToolBar.4`), always present.
   (Refresh/change/help hidden in "view only" mode.)
2. Message area (only when ≤1 certificate): 1 cert → sub-headline (custom or `"Confirme el certificado pulsando Aceptar. Si no es este
   el certificado que desea usar pulse Cancelar."` `.1`); 0 certs → `"No se han encontrado certificados válidos en el almacén. Inserte una
   tarjeta inteligente en el lector y pulse Recargar, o cargue un almacén externo."` (`.8`). Verdana 12, 370×40.
3. Separator.
4. Certificate list: single selection, row height **86 px**, width 500, visible rows `max(1, min(4, n))`, vertical scrollbar as needed,
   first row selected by default. Selected row: background `#D9EAFF`, border 1 px white + 1 px `#84ACDD`; unselected: window colour,
   empty border (2,2,2,4).

Sorting: by friendly name with `String.compareToIgnoreCase` (code-unit order, not locale collation); nulls last; ties unspecified.
Rust: same primary key; add deterministic secondary key (notAfter desc, then thumbprint).

### 8.4 Store switcher menu (`getAvailablesKeyStores`)
IDs: 1 system, 2 Firefox, 3 PKCS#12 file, 4 DNIe, 5 registered PKCS#11 card.
- Windows/macOS: `[system, Firefox, PKCS#12, DNIe]`.
- Linux: `[system, PKCS#12, DNIe]` if the current store (or its first sub-store) is `SHARED_NSS` — which, due to 3.6.10, is also the
  case for a freshly loaded Firefox store — else `[Firefox, PKCS#12, DNIe]` (NSS cannot be re-initialised in-process with another DB).
- Menu labels: `"Almacén de claves del sistema"`, `"Almacén de claves de Mozilla Firefox"`, `"Almacén de claves en fichero (PFX/PKCS#12)"`,
  `"DNI electrónico"` (`CertificateSelectionPanel.35–38`), then one item per **user** registered card, then per **system** card (label = card name).
Actions (`AOKeyStoreDialog.changeKeyStoreManager`):
- Firefox → `MOZ_UNI` (or `MOZ_UNI_WITH_OS` when invoked from the browser); sets last-selected store to the `MOZ_UNI` display name.
- PKCS#12 → file chooser (title `"Selección de almacén local"`, filter `"Almacenes de claves (*.p12, *.pfx)"`), password loop on wrong
  password (`"Contraseña incorrecta."`); records last-selected store + file.
- DNIe → `DNIEJAVA` with `forceReset=true`.
- System → OS default (1.2).
- Registered card → `PKCS11` with the card's library; records name + library.
- Errors → `"Error al cargar el nuevo almacén de claves."` (`AOKeyStoreDialog.10`) titled `"Error"`; the old store stays.
- On success the dialog's store is **replaced** (not merged), list refreshed, title updated.
"Last selected store" is **in-memory only** (process lifetime) and influences the next protocol operation in the same process (9.2).

### 8.5 Row content per view

The selected view is persisted in Java pref node `/es/gob/afirma/ui/core/jse/certificateselection`, key `certView`, values
`PERSONAL` (default) / `REPRESENTATIVE` / `PSEUDONYM`; it is saved only when the user presses OK.

Common: left icon (8.7), 4 text lines, Verdana; line 1 bold 14 px; others plain 11 px; last line an underlined link
`"Haga clic aquí para ver las propiedades del certificado"` (`.5`).

| View | Line 1 | Line 2 | Line 3 | Tooltip |
|---|---|---|---|---|
| Personal (`"Vista de certificados personales"`) | friendly name | `"Emisor: <issuer CN>. Uso: <usage>."` (`.2`) — issuer CN taken from the RFC 2253 issuer string | `"Válido desde: dd/MM/yyyy hasta dd/MM/yyyy"` (`.3`) | `"Certificado emitido para <subject CN>. Estado: <vigente|caducado o aún no válido>."` (`.29`,`.30`,`.31`) |
| Representative (`"Vista de certificados de representante"`) | subject `O` (else friendly name) | `"Representante: <subject CN>"` (`.28`) | dates | `"Certificado de <line1> emitido para <CN>. Estado: …"` (`.32`) |
| Pseudonym (`"Vista de certificados de seudónimo"`) | `"<title> (<pseudonym>)"`, or `<title>`, or friendly name (title = 2.5.4.12, pseudonym = 2.5.4.65) | `"Organismo: <OU, else O>. Uso: <usage>."` (`.33`) or, if neither, the personal-view issuer line | dates | org present: `"Certificado de <title or CN> perteneciente a <org>. Estado: …"` (`.34`); else `.29` |

The properties link is **not shown on macOS** in the Representative and Pseudonym views (shown in Personal view).
Attribute values from the RFC 2253 string that are hex (`#…`) are decoded by skipping 5 chars (`#`+tag+1-byte length) and reading UTF-8.

`<usage>` text (`KeyUsage.toString`, core messages), with SIGN = nonRepudiation, AUTH = digitalSignature, CYPH = **dataEncipherment**:
no KeyUsage → `"Desconocido"`; SIGN∧AUTH∧CYPH → `"Firma, autenticación y cifrado"`; AUTH∧CYPH → `"Autenticación y cifrado"`;
SIGN∧AUTH → `"Firma y autenticación"`; AUTH → `"Autenticación"`; SIGN → `"Firma"`; CYPH → `"Cifrado"`; else `"Otros"`.
(`"Firma y cifrado"` exists but is unreachable — order bug; keep the order.)

### 8.6 Interaction
- Mouse: single click selects; **double click = OK** (unless view-only); single click inside the link bounds of the
  selected row opens the certificate viewer; hand cursor while hovering the link.
- Keyboard: Up/Down/PageUp/PageDown/Home/End in the list; **Enter = OK**; **Esc = Cancel**; **F1** = help; **F5** = refresh
  (key-released events, global dispatcher while the dialog is open); Tab navigates toolbar buttons (drop-downs open on Space/Enter
  and show the popup under the button).
- Refresh: `ksdm.refresh()` (re-init all sub-stores with `forceReset`; card PINs may be re-asked); on success list rebuilt and first
  row selected; failure logged, list unchanged. Wait cursor during refresh/view change/store change.
- High contrast (Windows `win.highContrast.on`): white text on window colour, yellow links, white icons (black when focused).

### 8.7 Icons (`CertificateIconManager`)
Issuer family from `getIssuerX500Principal().toString().toUpperCase()`:
ACCV if contains `O=Generalitat Valenciana` **and** `OU=PKIGVA` (**bug:** compared against an upper-cased string, never matches);
DNIe if contains `O=DIRECCION GENERAL DE LA POLICIA` and `OU=DNIE`; CNP if `O=DIRECCION GENERAL DE LA POLICIA` and `OU=CNP`;
FNMT if contains `O=FNMT`; else generic. State: **error** if `now >= notAfter || now <= notBefore`; **warning** if
`notAfter - now < 630 000 000 ms` (intended 7 days; `25*7` hours bug = 7 days 7 h); else normal.
Resources: `accvicon{,_w,_e}.png`, `dnieicon…`, `cnpicon…`, `fnmticon…`, `certicon…`. Accessible descriptions:
`"Certificado de DNIe dentro del periodo de validez"` / `"…a punto de caducar"` / `"…caducado o aun no válido"` (and CNP, FNMT-RCM,
ACCV, generic variants `CertificateSelectionPanel.4,7,9,11,13,15–24`). Rust: fix the ACCV comparison and use exactly 7 days
(document as intentional deviation) or keep parity flag.

### 8.8 "Ver certificado" (properties link)
Write the DER to a temp file `afirma*.cer` (deleted on exit) and:
- macOS: `osascript -e 'do shell script "qlmanage -p <path with spaces escaped>"'` (Quick Look; opening the file would import it).
- Others: `Desktop.open(file)` (Windows certificate viewer / `xdg-open`); Windows fallback `cmd /C start "Detalle del certificado" "<file>"`.
- If all fail: "Save as" dialog (`"Guardar certificado"`, default name `certificado.cer`, filter `"Certificado electrónico"`);
  errors `"Error al guardar el certificado en disco."` / `"La codificación del certificado es inválida"`.
Rust: Windows → `CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, …)` (native viewer without temp files);
macOS → `qlmanage -p` or `SFCertificatePanel` via objc; Linux → `xdg-open` (gcr-viewer).

### 8.9 Known dialog bugs (do not reproduce)
- If a row fails to render (e.g. KeyUsage with >9 bits throws, or empty chain), the row is skipped but `selectedIndex` still indexes
  the unfiltered bean array → **wrong certificate returned**. Rust: build rows and beans from the same filtered vector.
- `getShowedCertsCount` counts beans, not rendered rows.

### 8.10 Improvement ideas (optional, behind settings)
- Search box (filter by CN/issuer/serial), group by store/backend with a small store badge (Windows, Firefox, DNIe, PKCS#11 name).
- Show key type/size, "hardware token" indicator, qualified (QcCompliance/QcSSCD) badge, days to expiry, NIF/serialNumber.
- Built-in details pane (subject, issuer, serial, validity, KU/EKU, policies, chain, SHA-1/SHA-256 thumbprints) instead of external viewer.
- Auto-refresh on card insertion/removal; "Remember this certificate for this site" (with explicit consent) as an evolution of sticky.
- Explain why certificates are hidden ("3 certificados ocultos por filtros/caducados") with a toggle.
- Correct accessibility (screen reader announces CN, issuer, validity) and full keyboard operation of drop-downs.

---

## 9. Store selection logic

### 9.1 Name resolution (`SimpleKeyStoreManager.getKeyStore(name, invokedFromBrowser)`)
1. `null` → null.
2. For each enum constant: if `getName().equalsIgnoreCase(name.trim())` → that store (display-name match). If it is `MOZ_UNI` and
   `invokedFromBrowser` → `MOZ_UNI_WITH_OS`.
3. If `name` is a registered smart card (user or system map, exact key) → `PKCS11` (with display name set to `name`).
4. `AOKeyStore.valueOf(name)` (exact enum constant, **not trimmed, case-sensitive**) → that store (same MOZ_UNI→WITH_OS rule).
5. Otherwise log `"Almacen de claves no reconocido (<name>)"` and return null.
Accepted protocol values therefore include `WINDOWS`, `APPLE`, `MOZ_UNI`, `SHARED_NSS`, `PKCS12`, `PKCS11`, `DNIEJAVA`, `JAVA`,
`JCEKS`, `JAVACE`, `CERES`, `CERES_430`, `SMARTCAFE`, … and display names such as `Windows`, `windows`, `NSS`, `PKCS#12 / PFX`.
(`autoscript.js` constants: `WINDOWS, APPLE, PKCS12, PKCS11, MOZ_UNI, SHARED_NSS, JAVA, JCEKS, JAVACE, DNIEJAVA`.)

Validation of a *preference* value (`getValidKeyStoreType`): `MOZ_UNI` only if Firefox is available, `WINDOWS` only on Windows,
`APPLE` only on macOS; otherwise the OS default.

### 9.2 Protocol (browser) invocation
URL parameters (both may be present; `keystore` wins):
- `keystore` — plain text `"<STORE>"` or `"<STORE>:<lib-or-file>"`.
- `ksb64` — Base64 of the same text (autoscript encodes URL-safe in some paths; Java decodes with the **standard** alphabet only →
  a URL-safe value containing `-`/`_` fails to decode and is ignored). Rust: accept both alphabets.
Parsing (`UrlParameters`): store name = text before the **first** `:` (trimmed) or whole text; lib = text after the first `:` with
`"` and `'` removed, trimmed, then canonicalised (`File.getCanonicalPath`; Windows `PKCS12:C:\x.p12` → lib `C:\x.p12`). If the
decoded text is just `":"` → no store.

Store choice at operation time (`sign`, `signandsave`, `batch`, `selectcert`), first match wins:
1. **Sticky key** (5.5) → no store at all.
2. If a "last selected keystore" exists in this process (the user switched store in a previous dialog) → that store
   (`getLastSelectedKeystore`, validated like a preference).
3. Else if preference `useDefaultStoreInBrowserCalls` = true → preference `defaultKeystore` unless `"default"` (resolved with
   `invokedFromBrowser=true`); its lib = preference `defaultLocalKeystorePath` when the store is PKCS12/PKCS11.
4. Else the store requested in the URL (`invokedFromBrowser=true`, so `MOZ_UNI` becomes `MOZ_UNI_WITH_OS`); lib from the URL.
5. Else / unresolved → OS default (1.2).
Note: in step 2 the lib comes from the URL (or the pref when `useDefaultStoreInBrowserCalls`), **not** from the remembered lib
(gotcha: a remembered PKCS#11 card without URL lib prompts for a library file).

Preload: at the start of a protocol invocation a background thread (`LoadKeystoreTask`) opens a store computed as in steps 2–3
(ignoring PKCS#12/PKCS#11 defaults) and **falls back to the OS default unless the choice is one of `WINDOWS`, `APPLE`,
`SHARED_NSS`, `MOZ_UNI`** (note `MOZ_UNI_WITH_OS` is not in that list, so a browser-resolved Firefox default is replaced by the
OS store for preloading). When the operation needs a store equal to the preloaded type it waits for the thread and reuses its
manager (if it loaded without error); otherwise it opens a new one. Rust: same, with a `OnceCell`/join handle.

Dialog parameters in protocol flows: `checkPrivateKeys=true`, `showExpiredCertificates=true`, `checkValidity=true` (no effect),
filters/mandatory from extraParams, `libName` = file name of the lib (title suffix), `invocationFromBrowser=true`,
external stores allowed unless `disableopeningexternalstores`. Load errors → `SocketOperationException` with the store's
error code if controlled, else `LOADING_KEYSTORE_INTERNAL_ERROR` (SAF_08 `"Error accediendo al almacén de claves y certificados"`).
A progress dialog `ProgressInfoDialog.2` is shown while loading unless extraParam `headless=true`.

### 9.3 Local GUI
- Default store = preference `defaultKeystore` (default `"default"` → OS store; otherwise a display name or registered card name,
  validated per 9.1); lib = `defaultLocalKeystorePath` for PKCS12/PKCS11.
- Loaded asynchronously at main window start (`SimpleKeyStoreManagerWorker`) unless the DNIe start screen is shown (3.7.3).
- Failure: error `"No se ha podido obtener el almacén de claves por defecto: <name> . Se cargará el del sistema."`
  (`SimpleKeyStoreManager.11`, title `SimpleAfirma.7`) then the OS store; wrong PKCS#12 password → `"Contraseña incorrecta"`
  loop; cancel → `"Operación cancelada. Se cargará el almacén de claves del sistema."` (`.13`) and OS store.
- If the user switched store in the dialog, the next signing re-opens the last selected store (with remembered file/lib).
- Local signing dialog: `checkPrivateKeys=true`, `showExpired=pref showExpiredCerts`, `checkValidity=true`, filters 7.6, `mandatory=false`.

### 9.4 CLI (`CommandLineLauncher`)
`-store <value>` (help text `"Establece el almacen de claves. Por defecto, el del sistema"`):

| Value (exact, case-sensitive) | Store |
|---|---|
| absent or `auto` | macOS → `APPLE`; Windows → `WINDOWS`; else `SHARED_NSS` |
| `windows` | `WINDOWS` |
| `mac` | `APPLE` |
| `mozilla` | `MOZ_UNI` |
| `dni` or `dnie` | `DNIEJAVA` |
| `pkcs12:<p12file>` | `PKCS12`; path = text after `pkcs12:` (all occurrences of `pkcs12:` removed); existence/readability checked on the cleaned (quotes removed, canonical) path, but the **uncleaned** text is used as lib (quirk) |
| `pkcs11:<p11file>` | `PKCS11`; cleaned canonical path |
| other | error `"Tipo de almacen desconocido: <value>"` (`CommandLineLauncher.48`) |

Non-existing file → `"El fichero PKCS#12 indicado no existe: <p>"` / `"No se tienen permisos de lectura para el fichero PKCS#12 indicado: <p>"`
(and `PKCS#11` equivalents). Store opened with description `"CommandLine"`, parent null, password callback =
`CachePasswordCallback(-password)` if given else **null** (PKCS#12 then loads with null password; PKCS#11 without login).
Factory failures surface as `"El almacen de claves seleccionado no esta disponible: <msg>"` (`.49`).

Certificate selection:
- `sign/cosign/countersign`: requires `-alias` or `-filter` or `-certgui` (`"Se tiene que especificar un alias o un filtro para la seleccion del certificado de firma"`).
  `-alias` and `-filter` are mutually exclusive. `-certgui` → dialog (7.1) with `checkValidity=false`, `mandatory=false`,
  external stores per filter; the returned store may differ.
- `-filter`: the expression (single, `filters` key) is applied to **all** aliases (no private-key or expiry check unless in the
  expression); 0 matches → `"No se han encontrado certificados que se ajusten al filtro establecido"`; >1 → `"Se ha encontrado mas de un certificado a partir del fitro establecido"`.
- `-alias`: raw backend alias (as printed by `listaliases`). Entry password = `-password` or `"dummy"`. Missing key →
  `"No se ha podido obtener la referencia a la clave privada"` / `"No se hay ninguna entrada en el almacen con el alias indicado: <alias>"`.
- `listaliases`: prints raw aliases one per line, or `<afirma><result>ok</result><response><alias>…</alias>…</response></afirma>` with `-xml`.
- `batchsign`: needs `-alias` or `-filter`; error `"No se ha encontrado ninguna entrada en el almacen con el alias '<a>', puede listar las entradas actuales con el comando \"listaliases\""`.
Rust: keep raw alias compatibility per backend (3.1.3, 3.3.2, 3.4.1, 3.5.2) and additionally accept `sha1:<hex>` / `sha256:<hex>` aliases (improvement).

---

## 10. Preferences related to key stores

Main node `/es/gob/afirma/standalone/ui/preferences` (lookup: user → system (or admin-updated `/es/gob/afirma/standalone/ui/systempreferences`
when allowed) → defaults in `/properties/preferences.properties`). Writing a value equal to the system/default value removes the
user key.

| Key | Default | Meaning / where used |
|---|---|---|
| `defaultKeystore` | `default` | Default store for the local app (and for browser calls if next is true): `default` = OS store; else a store **display name** (`Windows`, `Llavero de Mac`, `NSS`, `Mozilla / Firefox (unificado)`, `PKCS#12 / PFX`, `DNIe y tarjetas FNMT-TIF`) or a registered card name |
| `defaultLocalKeystorePath` | empty | PKCS#12 file or PKCS#11 library for the default store |
| `useDefaultStoreInBrowserCalls` | `false` | Use `defaultKeystore` for protocol invocations (9.2 step 3) |
| `showExpiredCerts` | `false` | Local GUI: show expired certificates. Lockable ("protected") preference |
| `useOnlySignatureCertificates` | `false` | Local GUI filter nonRepudiation |
| `useOnlyAliasCertificates` | `false` | Local GUI filter pseudonym-only |
| `skipAuthCertDnie` | `true` | Local GUI: hide DNIe authentication certificate |
| `hideDnieStartScreen` | `false` | Do not show the "use DNIe / other certificate" start screen |
| `enabledJmulticard` | `true` | Enable built-in DNIe/CERES driver (1.5). Lockable |
| `jmulticardCachePassword` | `false` | Unused |
| `preferencesBlocked` | `false` | Admin lock: disables editing (in this panel: "use in browser calls" and "show expired" checkboxes) |
| jmulticard UI node `useCacheDni` / `useCacheCeres` | `false` | Initial state of "Recordar contraseña durante la sesión" |
| cert dialog node `certView` | (absent → `PERSONAL`) | Last certificate view |

Preferences panel "Almacenes de claves" (`PreferencesPanelKeystores`):
- Group `"Almacén por defecto"`: combo with OS-specific entries — Windows: `Windows` (+ `Mozilla / Firefox (unificado)` if Firefox
  available); macOS: `Llavero de Mac` (+ Firefox if available); Linux: `NSS`; then `PKCS#12 / PFX`, `DNIe y tarjetas FNMT-TIF`, then every
  registered card. Index 0 is saved as `default`. Choosing PKCS#12 opens a file chooser (`"Selección de almacén local"`, `*.p12, *.pfx`;
  cancel → back to index 0); choosing DNIe immediately tries to open the card (error `"No se ha podido cargar el DNIe"` → index 0);
  choosing a card stores its library as `defaultLocalKeystorePath`.
  Button `"Ver contenido"` (mnemonic V) opens the selection dialog in view-only mode with headline `"Contenido del almacén '<name>'"`
  and sub-headline `"Es posible que no todos los certificados mostrados estén disponibles para firmar electrónicamente."`; errors
  `"Error al recuperar el almacén por defecto seleccionado"`. (Bug: for system cards it reads the library from the user map.)
  Checkboxes `"Usar también en las llamadas a Autofirma desde el navegador"` and the DNIe start-screen option.
- Group `"Filtros de certificados"`: `"Permitir el uso de certificados caducados"`, `"Usar solo certificados específicos para firma en las
  firmas electrónicas (atributo de no repudio)"`, `"Usar exclusivamente certificados de seudónimo"`, `"Omitir certificado de autenticación de DNIe"`.
- Group `"Tarjetas inteligentes"`: text `"Agregue tarjetas inteligentes por medio de sus PKCS#11 para poder acceder directamente a sus certificados."`,
  combo (first item `"Seleccione una tarjeta"`, then user cards, then system cards), buttons `"Conectar"` (test: opens the PKCS#11 store
  with the card name as description → `"Conexión correcta con tarjeta inteligente."` / error `"Error al conectar con tarjeta inteligente"`),
  `"Agregar tarjeta"`, `"Modificar"`, `"Eliminar"` (disabled for system cards / when nothing selected).
  Add/Modify dialog (`"Agregar tarjeta como almacén de claves"` / `"Modificar tarjeta"`): fields `"Nombre de la tarjeta"`,
  `"Controlador PKCS#11"` + `"Examinar"` (chooser `"Seleccionar controlador"`, filter `"Controladores PKCS#11"` `*.dll` / `*.so, *.dylib` / `*.so`).
  Validation: empty → `"Rellene todos los campos"`; duplicate name → `"El nombre de tarjeta introducido ya se encuentra registrado…"`;
  duplicate library → `"El controlador introducido ya se encuentra registrado…"` (bug: Modify without renaming fails as duplicate).
  Delete confirm `"¿Desea eliminar la tarjeta seleccionada?"`.
- `"Restaurar"` (confirm `"¿Desea restaurar la configuración para los almacenes de claves?"`): deletes user-registered cards, clears the
  keystores user node, removes the 7 keystore preferences above.

---

## 11. Errors and messages

### 11.1 Key-store error codes (`KeyStoreErrorCode`)

| Code | Constant | Text |
|---|---|---|
| 102025 | `Hardware.SMARTCARD_LOCKED` | La tarjeta inteligente esta bloqueada |
| 201101 | `Internal.LOADING_KEYSTORE_INTERNAL_ERROR` | Error generico al cargar el almacen de certificados |
| 201103 | `Internal.LOADING_PRIVATE_KEY_ERROR` | Error al cargar la clave del certificado |
| 201106 | `Internal.LOADING_CERTIFICATE_ERROR` | Error al cargar el certificado suelto o en PKCS#7 |
| 201107 | `Internal.LOADING_WINDOWS_KEYSTORE_ERROR` | Error al cargar el almacen de certificados de Windows (also used, wrongly, for NSS init failures) |
| 201108 | `Internal.LOADING_MOZILLA_KEYSTORE_ERROR` | Error al cargar el almacen de certificados de Mozilla |
| 201109 | `Internal.LOADING_APPLE_KEYSTORE_ERROR` | Error al cargar el almacen de certificados Apple KeyRing |
| 201110 | `Internal.LOADING_PKCS12_KEYSTORE_ERROR` | Error al cargar el almacen de certificados PKCS#12 |
| 201111 | `Internal.LOADING_JAVA_KEYSTORE_ERROR` | Error al cargar el almacen de certificados JKS |
| 201112 | `Internal.LOADING_PUBLIC_WINDOWS_KEYSTORE_ERROR` | Error al cargar el almacen de certificados de claves publicas de Windows |
| 201113 | `Internal.LOADING_PKCS11_KEYSTORE_ERROR` | Error al cargar el almacen de certificados a traves del PKCS#11 |
| 201114 | `Internal.LOADING_JMULTICARD_KEYSTORE_ERROR` | Error al cargar el almacen de certificados con JMulticard |
| 201115 | `Internal.LOADING_FILE_CERTSTORE_ERROR` | Error al cargar un certificado desde fichero |
| 201116 | `Internal.UNDEFINED_DEFAULT_KEYSTORE` | No hay definido un almacen de claves por defecto para este sistema operativo |
| 300003 | `ThirdParty.SUN_MSCAPI_PROVIDER_NOT_FOUND` | No se ha encontrado el proveedor MSCAPI de Sun |
| 300004 | `ThirdParty.AFIRMA_MSCAPI_ADDRESBOOK_PROVIDER_NOT_FOUND` | No se ha encontrado el proveedor MSCAPI del Cliente @firma |
| 300005 | `ThirdParty.AFIRMA_SINGLE_CERT_PROVIDER_NOT_FOUND` | No se ha encontrado el proveedor SingleCert del Cliente @firma |
| 600011 | `Request.UNSUPPORTED_KEYSTORE` | El almacen de claves solicitado no es compatible con el entorno de ejecucion |

Related core/simple codes: 500001 CANCELLED_OPERATION; 501001 CERTIFICATE_NEEDED / NO_CERTS_FOUND_SIGNING ("No se han encontrado certificados
para realizar la seleccion"); 502001 NO_CERTS_FOUND_SELECTING_CERT; 504001 NO_CERTS_FOUND_SIGNING_BATCH ("…para realizar la firma del lote");
501003 INVALID_SMARTCARD_PIN; 511003 KEYSTORE_LOCKED; 511004 SMARTCARD_LOCKED; 200201 UNKNOWN_SELECTING_CERT_ERROR;
200114 ENCODING_SIGNING_CERTIFICATE.

Legacy protocol error mapping (`ProtocolInvocationLauncherErrorManager`, old protocol versions):

| Legacy code | Text | From |
|---|---|---|
| `SAF_08` | `Error accediendo al almacén de claves y certificados` | 201101 |
| `SAF_18` | `Error al descodificar el certificado de firma` | 200114 |
| `SAF_19` | `No hay ningun certificado válido en su almacén. Compruebe las fechas de caducidad e instale un certificado válido.` | 501001, 502001, 504001 |
| `SAF_52` | `El almacen de claves esta bloqueado` | 511003, 511004 |

### 11.2 Other user-visible messages (es_ES)
- Selection dialog empty: `CertificateSelectionPanel.8` (8.3).
- Store change errors: `"Error al cargar el nuevo almacén de claves."`; refresh error (logged only): `"Error al resfrescar el almacén de claves."` (sic).
- PKCS#11 login: `KeyStoreUtilities.5/.7/.8` (3.5.1).
- DNIe start-screen errors: 3.7.3.
- Local GUI: `"El almacén no contiene ningún certificado que se pueda usar para firmar."` (`SignPanel.29`);
  `"Se encontró un error durante la operación con el certificado seleccionado."` (`SignPanel.56`).

### 11.3 Rust error enum (suggested)
`Cancelled`, `CardCancelled`, `WrongPassword { retries_left }`, `PinLengthInvalid`, `Locked { smartcard: bool }`,
`NoCertificates`, `StoreUnavailable { store, alternative }`, `UnsupportedStore`, `LibraryNotFound(path)`, `Firefox(NotFound|NssNotFound|ProfileNotFound)`,
`CardNotPresent`, `InvalidCard`, `BurnedDnie`, `Pkcs11(rv)`, `Os(code)`, `SignatureVerificationFailed` — each mapped to the codes above.

---

## 12. Rust implementation notes (summary)

| Concern | Recommendation |
|---|---|
| Backend trait | `trait KeyBackend { fn kind(); fn entries() -> Vec<Entry>; fn chain(&Entry); fn has_private_key(&Entry); fn sign(&Entry, Alg, &[u8], &dyn PinUi) -> Vec<u8>; fn refresh(); fn is_preferred() }`; `AggregateStore` implements de-duplication by SHA-1 (parity) and alias namespacing |
| Windows | `windows` crate (`Win32_Security_Cryptography`, `Win32_Security_Cryptography_UI` for viewer); run dialogs/key ops on an STA thread with an HWND owner so PIN dialogs are parented |
| macOS | `security-framework` + `core-foundation`; avoid key export |
| PKCS#11 | `cryptoki` (+ `cryptoki-sys` for NSS `pReserved` init) |
| NSS | option A (softokn + modules) for parity, option B (`libnss3` FFI) recommended |
| PC/SC | `pcsc` crate; reader monitoring for refresh |
| PKCS#12 | `p12-keystore` or `openssl`; zeroize secrets |
| X.509 | `x509-cert`/`der` for parsing; implement Appendix A DN formatting for filters/CN |
| Preferences | Java-compatible storage locations are covered in the preferences spec; keep the node/key names listed in 3.9/10 |
| Threading | Store loading off the UI thread; PKCS#11 sessions are not thread-safe → one mutex per module |
| Security | never log PINs; log certificate serial/issuer CN only (as Java does) and replace the home dir with `USERHOME` in paths |

---

## 13. Parity checklist

| # | Feature | Java class(es) | Notes for Rust |
|---|---|---|---|
| 1 | Store ids, display names, protocol resolution | `AOKeyStore`, `SimpleKeyStoreManager.getKeyStore` | name match case-insensitive, `valueOf` exact; MOZ_UNI→WITH_OS from browser |
| 2 | OS default stores | `AOKeyStore.getDefaultKeyStoreTypeByOs` | Win/mac/Linux/Solaris |
| 3 | Factory dispatch and unsupported combos | `AOKeyStoreManagerFactory` | `UNSUPPORTED_KEYSTORE` 600011 |
| 4 | Aggregation + preferred de-dup by SHA-1 | `AggregatedKeyStoreManager` | alias namespacing fix |
| 5 | Windows MY store, CNG/CAPI signing | `CAPIKeyStoreManager`, `CAPIUnifiedKeyStoreManager` | temp-profile detection, CAPI refresh after probing |
| 6 | Windows temp profile known cards | `SmartCardUnifiedKeyStoreManager` | table 1.4 order, first success only |
| 7 | macOS keychain identities, serial de-dup | `AppleKeyStoreManager` | no key export (improvement) |
| 8 | PKCS#12 load, password order, retry loops | `Pkcs12KeyStoreManager`, `FileKeyStoreManager`, `AOKeyStoreDialog.openPkcs12KeyStore` | protocol: no retry |
| 9 | Generic PKCS#11, login at open, PIN error dialogs | `AOKeyStoreManagerHelperPkcs11`, `KeyStoreUtilities` | FNMT SHA1 mechanism disable |
| 10 | Firefox profiles.ini location (snap, XDG, env) | `MozillaKeyStoreUtilities.getProfilesIniPath` | add flatpak |
| 11 | profiles.ini parsing and profile choice | `ProfilesIni`, `NSPreferences` | dummy profile rule (10 files, key4/key3) |
| 12 | NSS lib discovery per OS + arch check | `MozillaKeyStoreUtilities{Windows,Unix,OsX}`, `ElfParser`, `MsPortableExecutable`, `BundledNssHelper` | fix aarch64 |
| 13 | NSS init string, sql:/ fallback, readOnly | `MozillaKeyStoreUtilities.createPKCS11NSSConfig/loadNSS` | slot 2 |
| 14 | Shared NSS DB discovery | `SharedNssUtil` | `~/.pki/nssdb`, chromium snap, `/etc/pki/nssdb` |
| 15 | External modules from pkcs11.txt / secmod.db | `Pkcs11Txt`, `AOSecMod` | first working module only |
| 16 | Known Windows modules, nssckbi purge, DNIe exclusion | `MozillaKeyStoreUtilities` | |
| 17 | MOZ_UNI_WITH_OS composition | `MozillaUnifiedWithOSKeyStoreManager` | OS store added after NSS |
| 18 | Mozilla aggregate caching quirks | `AOKeyStoreManagerFactory` | fix: per-id cache, honour forceReset |
| 19 | Preferred card probing order (DNIe→CERES430→CERES→SmartCafe) | `KeyStoreUtilities.addPreferredKeyStoreManagers` | env switches |
| 20 | DNIe/CERES driver (PC/SC, SM, PACE/CAN) | jmulticard 2.1 | port or OpenSC interim |
| 21 | DNIe PIN dialog, retries text, 4–16 chars, eye, Ctrl+P, paste | `InputPasswordSmartcardDialog`, `JSecurePasswordLabel`, `CommonPasswordCallback` | |
| 22 | DNIe signature confirmation dialog | `DialogBuilder`, `ConfirmSmartcardDialog`, `CustomAuthorizeCallback` | cached with PIN |
| 23 | CAN dialog with example image | `UIPasswordCallbackCan` | empty CAN on close |
| 24 | PIN cache 1 h, prefs `useCacheDni/useCacheCeres` | `DnieCacheCallbackHandler`, `SmartcardCacheCallbackHandler`, `ResetCacheTimerTask` | absolute timer |
| 25 | DNIe start-screen error dialogs | `SimpleKeyStoreManager` | |
| 26 | Candidate list (expiry, private key, filters, CN names) | `KeyStoreUtilities.getAliasesByFriendlyName`, `AOUtil.getCN` | |
| 27 | Filter parsing & combination (OR/AND, sort, default) | `CertFilterManager`, `MultipleCertificateFilter` | default expiry filter only when no filter key |
| 28 | Each filter type | `filters/*`, `filters/rfc/*` | fail-open RFC 2254, KU requires extension |
| 29 | Mandatory/auto-select single cert | `CertFilterManager.isMandatoryCertificate`, `AOKeyStoreDialog.show` | `headless`, `mandatoryCertSelection=false` |
| 30 | Disable store switching | `disableopeningexternalstores` → `allowOpenExternalStores` | |
| 31 | Local GUI preference filters | `SignPanel.getCertFilters` | `skipAuthCertDnie` default true |
| 32 | Dialog layout, sorting, messages, title with lib | `CertificateSelectionDialog`, `CertificateSelectionPanel` | 86 px rows, ≤4 visible |
| 33 | Three views + persisted `certView` | `DefaultCertificateLine`, `RepresentativeCertificateLine`, `PseudonymCertificateLine` | |
| 34 | Icons by issuer and validity | `CertificateIconManager` | fix ACCV, 7-day warning |
| 35 | Usage text | `es.gob.afirma.core.keystores.KeyUsage` | CYPH = dataEncipherment |
| 36 | Keyboard/mouse (F1, F5, Enter, Esc, double-click, link) | `CertificateSelectionDispatcherListener`, `CertLinkMouseListener` | |
| 37 | "Ver certificado" per OS | `CertificateUtils.openCert` | native viewers |
| 38 | Store switcher menu & actions, last-selected store | `AOKeyStoreDialog.changeKeyStoreManager*`, `KeyStorePreferencesManager` | Linux list rule |
| 39 | Refresh | `CertificateSelectionDialog.refreshKeystore`, `AggregatedKeyStoreManager.refresh` | |
| 40 | Protocol `keystore`/`ksb64` parsing | `UrlParameters.getKeyStoreName/getDefaultKeyStoreLib` | accept URL-safe Base64 |
| 41 | Protocol store precedence, preload task | `ProtocolInvocationLauncherSign/SignAndSave/Batch/SelectCert`, `LoadKeystoreTask`, `ProtocolInvocationLauncherUtil` | |
| 42 | Sticky signatory | `ProtocolInvocationLauncher.stickyKeyEntry` | keep handles alive |
| 43 | Signing alg naming, PKCS#1/ECDSA DER, post-sign verification | `AOSignConstants`, `AOPkcs1Signer` | DigestInfo table B |
| 44 | PIN-error re-selection via `encodedcert` | protocol launchers, `SignPanelSignTask` | |
| 45 | CLI `-store/-alias/-filter/-certgui/-password/listaliases` | `CommandLineLauncher`, `CommandLineParameters` | raw alias compatibility |
| 46 | Local GUI default store & fallbacks | `SimpleKeyStoreManager`, `SimpleAfirma.getAOKeyStoreManager` | |
| 47 | Registered smart cards (user/system) | `KeyStorePreferencesManager`, `PreferencesPanelKeystores`, `SmartCardPanel` | node layout `/es/gob/afirma/core/keystores/<n>` |
| 48 | Preferences keys/defaults | `PreferencesManager`, `preferences.properties` | table 10 |
| 49 | Error codes | `KeyStoreErrorCode`, `ErrorCode`, `SimpleErrorCode`, `ProtocolInvocationLauncherErrorManager` | table 11 |
| 50 | Env/system switches | `KeyStoreUtilities`, `MozillaKeyStoreUtilities`, `MozillaUnifiedKeyStoreManager`, `JMulticardUtilities` | table 1.5 |
| 51 | Obsolete stores (address book, CA, JKS, JCEKS, SINGLE) | `AOKeyStoreManagerHelperCapiAddressBook`, `MSCAPIAddressBook`, `SingleCertKeyStore` | low priority |

---

## Appendix A — Java DN string formats used by filters and display

Several features operate on **strings**, so the Rust code must render DNs exactly like Java:

1. **`X500Principal.toString()` / `getSubjectDN().toString()`** (used by `getCN`, `*.contains`, RFC 2254 filter, icons):
   - RDNs in **reverse DER order** (most specific first, e.g. `CN=…, OU=…, O=…, C=ES`), separator `", "`; multi-valued RDN AVAs joined with `" + "`.
   - Keywords by OID: `CN` 2.5.4.3, `C` 2.5.4.6, `L` 2.5.4.7, `ST` 2.5.4.8, `O` 2.5.4.10, `OU` 2.5.4.11, `T` 2.5.4.12, `IP`
     1.3.6.1.4.1.42.2.11.2.1, `STREET` 2.5.4.9, `DC` 0.9.2342.19200300.100.1.25, `DNQ` 2.5.4.46, `SURNAME` 2.5.4.4,
     `GIVENNAME` 2.5.4.42, `INITIALS` 2.5.4.43, `GENERATION` 2.5.4.44, `EMAILADDRESS` 1.2.840.113549.1.9.1, `UID`
     0.9.2342.19200300.100.1.1, `SERIALNUMBER` 2.5.4.5; any other OID → `OID.<dotted>` (e.g. `OID.2.5.4.97=VATES-Q2826004J`).
   - String values are wrapped in `"…"` when they contain any of `, + = \n < > # ; \ "`, start with a space/newline, end with a
     space/newline, or contain two consecutive spaces; inside, `"` and `\` are backslash-escaped. Non-string values are `#` + hex DER.
2. **`X500Principal.getName()` (RFC 2253)** (used by `isPseudonymCert`, subject `serialNumber` comparison, `PrincipalStructure`,
   personal-view issuer CN): reverse order, separator `","` (no space), keywords only `CN, C, L, ST, O, OU, STREET, DC, UID`;
   all other attributes as dotted OID with `#` + **lowercase** hex of the value's DER encoding
   (e.g. `2.5.4.5=#13093132333435363738` ; `2.5.4.65=#0c…`); RFC 2253 backslash escaping (`\,` `\+` `\"` `\\` `\<` `\>` `\;`, leading `#`/space, trailing space).
   (In format 1 the non-string `#` form uses **uppercase** hex.) Comparisons in the filters are case-insensitive, so only
   consistency matters.
3. `getCN(principal)` / `getRDNvalueFromLdapName(rdn, principal)`: case-insensitive search of `<rdn>` preceded by start, `,` or space,
   followed by optional spaces and `=`; value = quoted content up to the next `"`, else up to the next `,` (trimmed). No unescaping.

## Appendix B — DigestInfo prefixes for RSA PKCS#1 v1.5 (when the backend signs a pre-computed hash)

| Hash | DER prefix (hex) to prepend to the digest |
|---|---|
| SHA-1 | `30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14` |
| SHA-224 | `30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c` |
| SHA-256 | `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20` |
| SHA-384 | `30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30` |
| SHA-512 | `30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40` |

ECDSA: hash the data, sign the hash (left-truncated to the curve order bit length), output `SEQUENCE { INTEGER r, INTEGER s }`
with minimal positive INTEGER encodings. Java always returns DER for `SHAxxxwithECDSA`.

## Appendix C — Important gotchas (quick list)

1. Default protocol filter hides expired certificates **only if no filter key is supplied**.
2. Browser flows do not hide the DNIe authentication certificate by default; the local GUI does (`skipAuthCertDnie=true`).
3. `KeyUsageFilter` rejects certificates without KeyUsage extension; `keyusage.x:yes` means false.
4. RFC 2254 filter errors let certificates through (fail-open); invalid `thumbprint` items are silently dropped → may accept all.
5. Only the **first** working Firefox external PKCS#11 module is loaded, and none when a DNIe/CERES is found by the built-in driver.
6. `SHARED_NSS` reads external modules from the **Firefox** profile `pkcs11.txt`.
7. Loaded Firefox stores report type `SHARED_NSS` (title "NSS"); `MOZ_UNI` and `MOZ_UNI_WITH_OS` share one process cache.
8. Linux aarch64 cannot find NSS in Java (arch check). Flatpak Firefox profiles are not discovered.
9. PKCS#11 PIN is asked when the store opens (before the dialog); DNIe/CERES PIN when signing; Windows/macOS by the OS.
10. jmulticard PIN cache: 1 h from first entry, also caches the DNIe "confirm signature" answer.
11. The selection dialog can return the wrong alias if a row fails to render; ACCV icon never shows; warning icon threshold is 7 d 7 h.
12. `AOKeyStore.PKCS11` display name is mutated globally by registered card usage.
13. URL `ksb64` must be standard Base64 in Java; autoscript may send URL-safe.
14. macOS Java exports keychain private keys (non-exportable/token keys fail at signing).
