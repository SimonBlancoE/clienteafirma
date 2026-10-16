# 07 — Core library (afirma-core) and cross-cutting signature plumbing

> Target: a 1:1 Rust reimplementation of AutoFirma (Cliente @firma) **1.9.1** (`pom.xml` `<version>1.9.1</version>`).
> This document describes `afirma-core` (`es.gob.afirma.core.*`), `afirma-core-prefs`, the top-level API of
> `afirma-crypto-validation`, and the format auto-selection logic of `afirma-simple`. It is written so that
> a Rust developer can implement the behaviour without reading the Java code. Where a Java behaviour is
> odd or buggy, it is documented as-is and flagged **GOTCHA** — parity means reproducing it unless the
> project decides otherwise.
>
> Out of scope (covered by sibling specs): the format-specific signers (CAdES, XAdES, PAdES, ODF, OOXML…),
> the full `afirma://` protocol (`es.gob.afirma.core.misc.protocol` is only summarised in §15), triphase
> server internals, keystore back-ends.

Conventions used below:

* "Properties" = `java.util.Properties` (a string→string map with Java's `.properties` text serialisation, see §3.6).
* `null` = absent / `Option::None`.
* Java `String.equals` is case-sensitive; `equalsIgnoreCase` is ASCII+Unicode simple case folding. All
  comparisons are case-sensitive unless stated.
* Logger name used everywhere: `"es.gob.afirma"` (LogManager uses `"es.gob"`). Log messages are not part of
  the contract, except where noted.

Contents: §1 constants · §2 algorithm names · §3 signer interfaces & extraParams · §4 AOSignerFactory & format auto-selection · §5 expPolicy expansion & AdESPolicy · §6 data-type detection · §7 Base64 & AOUtil · §8 platform/infrastructure utilities · §9 HTTP client & TLS · §10 exceptions & error codes (complete table) · §11 validation · §12 signers tree · §13 UI/keystore interfaces/prefs · §14 ASiC-S helpers · §15 protocol package (summary) · §16 parity checklist · §17 gotchas.

---

## 1. Constants (exact string values)

### 1.1 `AOSignConstants` — signature format names

| Java constant | Exact value | Notes |
|---|---|---|
| `SIGN_FORMAT_AUTO` | `auto` | Compared with `equalsIgnoreCase` everywhere ("AUTO", "Auto" accepted). Not registered in `AOSignerFactory`. |
| `SIGN_FORMAT_CMS` | `CMS/PKCS#7` | |
| `SIGN_FORMAT_CADES_ASIC_S` | `CAdES-ASiC-S` | |
| `SIGN_FORMAT_CADES_ASIC_S_TRI` | `CAdES-ASiC-S-tri` | |
| `SIGN_FORMAT_CADES` | `CAdES` | |
| `SIGN_FORMAT_CADES_TRI` | `CAdEStri` | (no hyphen) |
| `SIGN_FORMAT_PKCS1` | `NONE` | Raw PKCS#1 |
| `SIGN_FORMAT_PKCS1_ALT1` | `PKCS1` | **Not** registered in the factory |
| `SIGN_FORMAT_PKCS1_ALT2` | `PKCS#1` | **Not** registered in the factory |
| `SIGN_FORMAT_PKCS1_TRI` | `NONEtri` | |
| `SIGN_FORMAT_XADES_ASIC_S` | `XAdES-ASiC-S` | |
| `SIGN_FORMAT_XADES_ASIC_S_TRI` | `XAdES-ASiC-S-tri` | |
| `SIGN_FORMAT_XADES_DETACHED` | `XAdES Detached` | also used as value of the XAdES extraParam `format` |
| `SIGN_FORMAT_XADES_EXTERNALLY_DETACHED` | `XAdES Externally Detached` | **Not** registered in the factory |
| `SIGN_FORMAT_XADES_ENVELOPED` | `XAdES Enveloped` | |
| `SIGN_FORMAT_XADES_ENVELOPING` | `XAdES Enveloping` | |
| `SIGN_FORMAT_XADES` | `XAdES` | |
| `SIGN_FORMAT_XADES_TRI` | `XAdEStri` | |
| `SIGN_FORMAT_XMLDSIG_DETACHED` | `XMLDSig Detached` | |
| `SIGN_FORMAT_XMLDSIG_EXTERNALLY_DETACHED` | `XMLDSig Externally Detached` | **Not** registered in the factory |
| `SIGN_FORMAT_XMLDSIG_ENVELOPED` | `XMLDSig Enveloped` | |
| `SIGN_FORMAT_XMLDSIG_ENVELOPING` | `XMLDSig Enveloping` | |
| `SIGN_FORMAT_XMLDSIG` | `XMLDSig` | |
| `SIGN_FORMAT_OOXML` | `OOXML (Office Open XML)` | |
| `SIGN_FORMAT_OOXML_ALT1` | `OOXML` | |
| `SIGN_FORMAT_ODF` | `ODF (Open Document Format)` | |
| `SIGN_FORMAT_ODF_ALT1` | `ODF` | |
| `SIGN_FORMAT_PDF` | `Adobe PDF` | |
| `SIGN_FORMAT_PDF_TRI` | `Adobe PDF TriPhase` | |
| `SIGN_FORMAT_PADES` | `PAdES` | |
| `SIGN_FORMAT_PADES_TRI` | `PAdEStri` | (the task brief says "PAdES-tri": the real value is `PAdEStri`) |
| `SIGN_FORMAT_SOAP` | `SOAP` | **Not** registered in the factory (dead constant) |
| `SIGN_FORMAT_FACTURAE` | `FacturaE` | |
| `SIGN_FORMAT_FACTURAE_TRI` | `FacturaEtri` | |
| `SIGN_FORMAT_FACTURAE_ALT1` | `Factura-e` | |
| `DEFAULT_SIGN_FORMAT` | = `CAdES` | |

### 1.2 `AOSignConstants` — operations, profiles, modes

| Constant | Value |
|---|---|
| `MASSIVE_OPERATION_SIGN` | `FIRMAR` |
| `MASSIVE_OPERATION_COSIGN` | `COFIRMAR` |
| `MASSIVE_OPERATION_COUNTERSIGN_TREE` | `CONTRAFIRMAR_ARBOL` |
| `MASSIVE_OPERATION_COUNTERSIGN_LEAFS` | `CONTRAFIRMAR_HOJAS` |
| `DEFAULT_MASSIVE_OPERATION` | = `FIRMAR` |
| `SIGN_PROFILE_ADVANCED` | `advanced` |
| `SIGN_PROFILE_BASELINE` | `baseline` |
| `DEFAULT_SIGN_PROFILE` | = `advanced` |
| `SIGN_MODE_EXPLICIT` | `explicit` (data NOT included) |
| `SIGN_MODE_IMPLICIT` | `implicit` (data included) |
| `DEFAULT_SIGN_MODE` | = `explicit` |

### 1.3 `AOSignConstants` — CMS content types, OIDs, PDF subfilters

| Constant | Value |
|---|---|
| `CMS_CONTENTTYPE_DATA` | `Data` |
| `CMS_CONTENTTYPE_SIGNEDDATA` | `SignedData` |
| `CMS_CONTENTTYPE_DIGESTEDDATA` | `DigestedData` |
| `CMS_CONTENTTYPE_COMPRESSEDDATA` | `CompressedData` |
| `CMS_CONTENTTYPE_ENCRYPTEDDATA` | `EncryptedData` |
| `CMS_CONTENTTYPE_ENVELOPEDDATA` | `EnvelopedData` |
| `CMS_CONTENTTYPE_SIGNEDANDENVELOPEDDATA` | `SignedAndEnvelopedData` |
| `CMS_CONTENTTYPE_AUTHENTICATEDDATA` | `AuthenticatedData` |
| `CMS_CONTENTTYPE_AUTHENVELOPEDDATA` | `AuthEnvelopedData` |
| `DEFAULT_CMS_CONTENTTYPE` | = `EnvelopedData` |
| `DEFAULT_OID_TO_SIGN` | `1.3.6.1.4.1.1466.115.121.1.40` (LDAP "Octet String" syntax OID) |
| `PADES_SUBFILTER_BASIC` | `adbe.pkcs7.detached` |
| `PADES_SUBFILTER_BES` | `ETSI.CAdES.detached` |

### 1.4 `AOSignConstants` — algorithms

| Constant | Value |
|---|---|
| `DIGEST_ALGORITHM_SHA1` | `SHA1` |
| `DIGEST_ALGORITHM_SHA256` | `SHA256` |
| `DIGEST_ALGORITHM_SHA384` | `SHA384` |
| `DIGEST_ALGORITHM_SHA512` | `SHA512` |
| `SIGN_ALGORITHM_SHA1WITHRSA` | `SHA1withRSA` |
| `SIGN_ALGORITHM_SHA256WITHRSA` | `SHA256withRSA` |
| `SIGN_ALGORITHM_SHA384WITHRSA` | `SHA384withRSA` |
| `SIGN_ALGORITHM_SHA512WITHRSA` | `SHA512withRSA` |
| `SIGN_ALGORITHM_NONEWITHRSA` | `NONEwithRSA` |
| `SIGN_ALGORITHM_SHA1WITHDSA` | `SHA1withDSA` |
| `SIGN_ALGORITHM_SHA1WITHECDSA` | `SHA1withECDSA` |
| `SIGN_ALGORITHM_SHA224WITHECDSA` | `SHA224withECDSA` |
| `SIGN_ALGORITHM_SHA256WITHECDSA` | `SHA256withECDSA` |
| `SIGN_ALGORITHM_SHA384WITHECDSA` | `SHA384withECDSA` |
| `SIGN_ALGORITHM_SHA512WITHECDSA` | `SHA512withECDSA` |
| `SIGN_ALGORITHM_NONEWITHECDSA` | `NONEwithECDSA` |
| `DEFAULT_SIGN_ALGO` | = `SHA512withRSA` |

### 1.5 `CounterSignTarget` (enum)

| Enum | `toString()` | `getTarget(name)` accepts (after `trim()`, case-insensitive) |
|---|---|---|
| `SIGNERS` | `signers` | `signers` — `targets` are signer Common Names (Strings) |
| `NODES` | `nodes` | `nodes` — `targets` are node indexes (Integers, preorder index in the signers tree; exact semantics in the CAdES/XAdES specs) |
| `TREE` | `tree` | `tree` — counter-sign every node |
| `LEAFS` | `leafs` | `leafs` — counter-sign only leaf nodes |

`getTarget(null)` → `IllegalArgumentException("El objetivo de la contrafirma no puede ser nulo")`; unknown → `IllegalArgumentException("Objetivo no soportado: " + n)`.

### 1.6 Other core constants

| Where | Constant | Value |
|---|---|---|
| `MimeHelper` | `UNKNOWN_JMIMEMAGIC_VALUE` | `???` |
| `MimeHelper` | `DEFAULT_MIMETYPE` | `application/octet-stream` |
| `MimeHelper` | `DEFAULT_CONTENT_DESCRIPTION` | `binary` |
| `MimeHelper` | `DEFAULT_CONTENT_OID_DATA` | `1.2.840.113549.1.7.1` |
| `OfficeAnalizer` | fallback mimetype (typo!) | `application/octect-stream` (**GOTCHA**: misspelt, differs from `MimeHelper.DEFAULT_MIMETYPE`) |
| `OfficeAnalizer`, `ASiCUtil` | `THRESHOLD_FILE_SIZE` | `1000000000` bytes (1 GB, decimal) |
| `ASiCUtil` | ASiC-S mimetype | `application/vnd.etsi.asic-s+zip` |
| `ASiCUtil` | `ENTRY_NAME_BINARY_SIGNATURE` | `META-INF/signature.p7s` |
| `ASiCUtil` | `ENTRY_NAME_XML_SIGNATURE` | `META-INF/signatures.xml` |
| `ASiCUtil` | mimetype entry name | `mimetype` |
| `ASiCUtil` | default data object name | `dataobject.<ext>`; `<ext>` from `MimeHelper.getExtension()` or `bin` |
| `ExtraParamsProcessor` | expandable policy key | `expPolicy` |
| `ExtraParamsProcessor` | `MAX_PATH_SIZE` | `255` |
| `ExtraParamsProcessor` | 1 MB | `1024*1024` = 1048576 |
| `AdESPolicyPropertiesManager` | `POLICY_ID_AGE` | `FirmaAGE` |
| `AdESPolicyPropertiesManager` | `POLICY_ID_AGE_1_8` | `FirmaAGE18` |
| `AdESPolicy` | default hash algorithm when computing a policy hash | `SHA-512` |
| `UrlHttpManager` | `DEFAULT_TIMEOUT` | `-1` (= "use platform default") |
| `UrlHttpManagerImpl` | `JAVA_PARAM_DISABLE_SSL_CHECKS` (JVM system property) | `disableSslChecks` |
| `UrlHttpManagerImpl` | `JAVA_PARAM_SECURE_DOMAINS_LIST` (JVM system property) | `secureDomainsList` |
| `SSLErrorProcessor` | extraParam | `headless` |
| `SSLErrorProcessor` | extraParam | `sslOmitImportationDialog` |
| `SSLErrorProcessor` | `SYSTEM_PREFERENCE_BLOCK_AUTO_IMPORT_TRUSTED_CERTS` (JVM system property) | `blockAutoImportTrustedCerts` |
| `TrustStoreManager` | trust store path | `<user.home>/.afirma/TrustedCertsKeystore.jks` (JKS, password `changeit`) |
| `LogManager` | `SUBDIR` | `.afirma` |
| `LogManager` | log file | `<user.home>/.afirma/<APP>.afirma.log.xml`, max 2 MiB (`1024*1024*2`), 1 file, overwrite (not append), `java.util.logging.XMLFormatter` format |
| `LoggerUtil` | system property | `allow.extended.logs` (if true, do not truncate logged strings at 200 chars) |
| `AOPkcs1Signer` | signed file suffix | `.p1` |
| `SignaturePolicyIncompatibilityException` | param to set on confirmation | `avoidAGEPolicyIncompatibilities` |
| `SignaturePolicyIncompatibilityException` | requestor text keys | `agePolicyIncompatibilitySign`, `agePolicyIncompatibilityCosign`, `agePolicyIncompatibilityCounterSign`; ops `OP_SIGN=1`, `OP_COSIGN=2`, `OP_COUNTERSIGN=3` |
| `SigningLTSException` | param to set on confirmation | `allowSignLTSignature` |
| `SigningLTSException` | requestor text keys | `signingLts`, `signingLtsPossible` |
| `AOSignInfo` | format when constructed with `null` | `Desconocido` |
| `LogManager.App` | enum names | `MINIAPPLET, APPLET, AUTOFIRMA, AUTOFIRMA_CONFIGURATOR, STANDALONE, ANDROID, HANDWRITTEN, DNINB, OTHER` |
| `KeyStoreDialogManager` | keystore ids | `KEYSTORE_ID_SYSTEM=1`, `KEYSTORE_ID_MOZILLA=2`, `KEYSTORE_ID_PKCS12=3`, `KEYSTORE_ID_DNIE=4`, `KEYSTORE_ID_PKCS11=5` |
| `ProtocolVersion` | versions | `"0"`, `"1"`, `"2"`, `"3"`, `"4"`, `"4.1"` |
| `ErrorCode` | category prefixes | `ERROR_HARDWARE="1"`, `ERROR_INTERNAL="2"`, `ERROR_THIRD_PARTY="3"`, `ERROR_COMMUNICATION="4"`, `ERROR_FUNCTIONAL="5"`, `ERROR_REQUEST="6"`, `ERROR_REQUEST_FROM_BROWSER="62"`, `ERROR_TRIPHASE_SERVICE="3004"` |

### 1.7 Cipher constants (`es.gob.afirma.core.ciphers.CipherConstants`)

`AOCipherAlgorithm` (name, description, supportsPassword, supportsKey, OID) — default `AES`:

| Enum | name | password? | key? | OID |
|---|---|---|---|---|
| AES | `AES` | no | yes | `2.16.840.1.101.3.4.1` |
| BLOWFISH | `Blowfish` | no | yes | `1.3.6.1.4.1.3029.1.1.1` |
| DES | `DES` | no | yes | `1.2.840.113549.3.6` |
| TRIPLEDES | `DESede` | no | yes | `1.2.840.113549.3.7` |
| PBEWITHMD5ANDDES | `PBEWithMD5AndDES` | yes | no | `1.2.840.113549.1.5.3` |
| PBEWITHSHA1ANDDESEDE | `PBEWithSHA1AndDESede` | yes | no | `1.2.840.113549.1.5.10` |
| PBEWITHSHA1ANDRC2_40 | `PBEWithSHA1AndRC2_40` | yes | no | `1.2.840.113549.1.5.11` |
| HMACMD5 | `HmacMD5` | no | yes | `1.3.6.1.5.5.8.1.1` |
| HMACSHA1 | `HmacSHA1` | no | yes | `1.2.840.113549.2.7` |
| HMACSHA256 | `HmacSHA256` | no | yes | `1.2.840.113549.2.9` |
| HMACSHA384 | `HmacSHA384` | no | yes | `1.2.840.113549.2.10` |
| HMACSHA512 | `HmacSHA512` | no | yes | `1.2.840.113549.2.11` |

`AOCipherPadding`: `PKCS5PADDING`, `ISO10126PADDING`, `NOPADDING`. `AOCipherBlockMode`: `ECB`, `CBC`, `PCBC`, `CTR`, `CFB`, `OFB`.
`AOCipherConfig(algo, mode, padding)`: null algo → AES; null mode → `CBC` for the three PBE algorithms, else `ECB`; null padding → `PKCS5PADDING`. `parse("ALGO[/MODE/PADDING]")` splits on `/`; algo by case-insensitive name (unknown → `NoSuchAlgorithmException`); mode/padding only read if exactly 3 parts. `toString()` = `name/MODE/PADDING`.
`AOCipher` / `AOEnveloper` are interfaces only (implemented in `afirma-crypto-cipher*`, `afirma-crypto-cms-enveloper`); not used by AutoFirma signing flows.

---

## 2. Algorithm-name normalisation

### 2.1 `AOSignConstants.getDigestAlgorithmName(String pseudoName) -> String`

Exact algorithm (order matters; `U` = `pseudoName.toUpperCase(Locale.US)`):

1. `pseudoName == null` → `IllegalArgumentException("El nombre del algoritmo de huella digital no puede ser nulo")`.
2. If `U == "SHA"` or `U == "HTTP://WWW.W3.ORG/2000/09/XMLDSIG#SHA1"` or `U == "1.3.14.3.2.26"` or `U.startsWith("SHA1")` or `U.startsWith("SHA-1")` → return **`"SHA1"`** (no hyphen!).
3. If `U == "HTTP://WWW.W3.ORG/2001/04/XMLENC#SHA256"` or `U == "2.16.840.1.101.3.4.2.1"` or starts with `SHA256` or `SHA-256` → `"SHA-256"`.
4. If `U` starts with `SHA384` or `U == "2.16.840.1.101.3.4.2.2"` or starts with `SHA-384` → `"SHA-384"`. (No URI form is recognised here.)
5. If `U == "HTTP://WWW.W3.ORG/2001/04/XMLENC#SHA512"` or `U == "2.16.840.1.101.3.4.2.3"` or starts with `SHA512` or `SHA-512` → `"SHA-512"`.
6. If `U == "HTTP://WWW.W3.ORG/2001/04/XMLENC#RIPEMD160"` or starts with `RIPEMD160` or `RIPEMD-160` → `"RIPEMD160"`.
7. If the **original** string contains `"with"` (case-sensitive) → recurse on `pseudoName.substring(0, indexOf("with"))`.
8. If the original starts with `http://www.w3.org/2001/04/xmldsig-more#`, `http://www.w3.org/2000/09/xmldsig#` or `http://www.w3.org/2009/xmldsig11#` → recurse on the substring after the **last** `-`.
9. Otherwise log a warning and return `pseudoName` unchanged.

Examples: `"SHA512withRSA"`→`SHA-512`; `"sha-256"`→`SHA-256`; `"SHA224withECDSA"`→`SHA224` (unrecognised, returned as-is after step 7); `"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"`→`SHA-256`; `"MD5withRSA"`→`MD5`.
**GOTCHA**: `"http://www.w3.org/2001/04/xmldsig-more#sha384"` (the XML digest URI for SHA-384) → step 8 cuts after the `-` of `xmldsig-more` → `"more#sha384"` → no rule matches → returned as `"more#sha384"`.

### 2.2 `composeSignatureAlgorithmName(String algorithm, String keyType) -> String`

* null algorithm → `IllegalArgumentException("El nombre del algoritmo no puede ser nulo")`; null keyType → `IllegalArgumentException("El tipo de clave de certificado no puede ser nulo")`.
* `digest = getDigestAlgorithmName(algorithm).replace("-", "")` → e.g. `SHA1`, `SHA256`, `SHA384`, `SHA512`, `RIPEMD160`.
* Suffix: keyType `"RSA"` → `withRSA`; `"DSA"` → `withDSA`; keyType starting with `"EC"` → `withECDSA`; else `IllegalArgumentException("Tipo de clave de firma no soportado: " + keyType)`.
* `keyType` is Java's `Key.getAlgorithm()` string (`"RSA"`, `"DSA"`, `"EC"`). The Rust key abstraction must expose the same strings.
* Result examples: (`SHA512withRSA`, `EC`) → `SHA512withECDSA`; (`SHA-256`, `RSA`) → `SHA256withRSA`.

### 2.3 Predicates

* `isSHA2SignatureAlgorithm(a)`: `a` ∈ {`SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`, `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA`} (exact, case-sensitive; `SHA224withECDSA` → false).
* `isSHA1SignatureAlgorithm(a)`: `a` ∈ {`SHA1withRSA`, `SHA1withDSA`, `SHA1withECDSA`}.
* `isDSAorECDSASignatureAlgorithm(a)`: non-null and ends with `withECDSA`, `withECDSAinP1363Format`, `withDSA` or `withDSAinP1363Format`.

### 2.4 `Pkcs1Utils` (ECDSA/DSA signature encodings)

* `encodeSignature(byte[] raw)`: raw = `r || s` (two equal halves, `n = len/2`); returns DER `SEQUENCE { INTEGER r, INTEGER s }` (r, s as unsigned big integers, minimal DER INTEGER encoding with leading 0x00 when the high bit is set). Errors → `SignatureException("Could not encode signature")`.
* `decodeSignature(byte[] der)`: strict DER parse of a SEQUENCE of exactly 2 INTEGERs with no trailing bytes; each converted to unsigned bytes with leading zeros trimmed; `k = max(len(r), len(s))`; output `2k` bytes, `r` right-aligned in the first half, `s` right-aligned in the second. (Note: `k` is the max actual length, **not** the curve size.) Errors → `SignatureException("Invalid encoding for signature")`.
* The `es.gob.afirma.core.signers.der.*` package is a copy of `sun.security.util` DER classes used only by `Pkcs1Utils`; in Rust use any DER library.

---

## 3. Signer interfaces and `extraParams`

### 3.1 Interface hierarchy

```
AOSimpleSigner  : sign(data, algorithm, key, certChain, extraParams) -> bytes
AOCoSigner      : cosign(data, sign, algorithm, key, certChain, extraParams) -> bytes
                  cosign(sign, algorithm, key, certChain, extraParams) -> bytes
AOCounterSigner : countersign(sign, algorithm, targetType, targets[], key, certChain, extraParams) -> bytes
AOSigner extends AOCoSigner, AOCounterSigner, AOSimpleSigner, plus:
    getSignersStructure(sign, asSimpleSignInfo) -> AOTreeModel
    getSignersStructure(sign, params, asSimpleSignInfo) -> AOTreeModel
    isSign(data) -> bool
    isSign(data, params) -> bool
    isValidDataFile(data) -> bool
    getSignedName(originalName, inText) -> String
    getData(signData) -> bytes|null
    getData(sign, params) -> bytes|null
    getSignInfo(signData) -> AOSignInfo
    getSignInfo(data, params) -> AOSignInfo
abstract class AOTriphaseSigner implements AOSigner { protected UrlHttpManager httpConnection; setHttpConnection(..) }
interface OptionalDataInterface { boolean needData(String cryptoOperation, Properties config) }   // impl: AOXAdESSigner, AOXAdESTriPhaseSigner
interface AOConfigurableContext { setSecureMode(boolean); isSecureMode() }                       // impl: AOPDFSigner
interface SignEnhancer { byte[] enhance(byte[] signature, Properties options) throws IOException } // e.g. long-term upgrade (plugins)
```

All methods may throw `AOException` (checked) and `IOException`; `getSignersStructure` may throw `AOInvalidSignatureFormatException`. Unsupported operations throw Java `UnsupportedOperationException` (unchecked) — e.g. countersigning OOXML, any multisign in `NONE`.

Parameters (common contract):

| Parameter | Meaning |
|---|---|
| `data` | Bytes to sign (content). For co-sign with `data`, the original data the existing signature covers (used by explicit/detached formats). |
| `sign` | Existing signature (or signed document: PDF/ODF/OOXML/XML). |
| `algorithm` | Signature algorithm name, normally one of §1.4 (e.g. `SHA512withRSA`). Implementations normalise via `composeSignatureAlgorithmName(algorithm, key.getAlgorithm())`, so a digest name or an RSA name used with an EC key are accepted and converted. |
| `key` | Private key (opaque handle in Rust: PKCS#11/CAPI/NSS/file keys). |
| `certChain` | Signer certificate chain, `[0]` = signer cert. |
| `extraParams` | `Properties`; may be `null` (implementations must treat `null` as empty). Signers generally work on a copy (e.g. `AOPDFSigner` clones it); callers must not rely on signer-side mutations, except the explicit in-place helpers of §3.5. |
| `targetType`/`targets` | See §1.5. |
| `asSimpleSignInfo` | `true` → tree nodes carry `AOSimpleSignInfo`; `false` → tree nodes carry the signer CN `String`. |
| `params` (isSign/getData/getSignInfo/getSignersStructure) | Format-specific hints (e.g. PDF password `headless`, `ownerPassword`, …). May be null. |

Return/edge contracts:

* `isSign(x)` == `isSign(x, null)` for every signer. Must never throw on garbage input (they catch and return `false`), except `IOException` is declared.
* `getData` returns `null` when the signature does not contain the data (explicit/detached). Throws `AOInvalidSignatureFormatException` if not a signature of that format.
* `getSignedName(originalName, inText)` — suggested output file name; each signer has its own rule, e.g. CAdES `name + inText + ".csig"`, XAdES `name + inText + ".xsig"`, XAdES-ASiC-S `… + ".asics"`, NONE `….p1`, PDF `x.pdf`→`x.signed.pdf` (null → `signed.pdf`; details in the format specs). `inText` (may be null → "") is inserted before the suffix.
* `getSignInfo` returns `AOSignInfo` (§12.3).

### 3.2 `AOPkcs1Signer` (format `NONE`) — full behaviour

`sign(data, algorithm, key, certChain, extraParams)`:

1. `algorithm == null` → `IllegalArgumentException("Es necesario indicar el algoritmo de firma, no puede ser nulo")`.
2. Provider selection: if `extraParams != null`, provider name = `extraParams["Provider." + <Java class name of key>]` (Java-only; Rust: ignore, but keep reserved).
3. `algorithmName = composeSignatureAlgorithmName(algorithm, key.getAlgorithm())` (unknown key type → `IllegalArgumentException`, propagates). Unknown algorithm → `AOException("No se soporta el algoritmo de firma (<alg>): …", UNSUPPORTED_SIGNATURE_ALGORITHM 600107)`.
4. `initSign` failure → `AOException(…, INVALID_SIGNING_KEY 200110)`.
5. `update(data)` failure → `AOException(…, SIGNING_PKCS1_ERROR 200111)`.
6. `sign()` failure mapping:
   * `es.gob.jmulticard.CancelledOperationException` → `AOCancelledSMOperationException("Cancelacion del dialogo de JMulticard")` (code 500001).
   * `es.gob.jmulticard.jse.provider.SignatureAuthException` with cause `AuthenticationModeLockedException` → `LockedKeyStoreException("El almacen de claves esta bloqueado", SMARTCARD_LOCKED 511004)`; cause `BadPinException` → `PinException("La contrasena del almacen o certificado es incorrecta", INVALID_SMARTCARD_PIN 501003)`; other cause → `AuthenticationException(…)` (code 200108).
   * Anything else → `AOException("Error durante el proceso de firma PKCS#1: …", SIGNING_PKCS1_ERROR 200111)`.
7. **Self-verification (ETSI TS 119 102-1)**: if `certChain` non-empty, verify the produced signature over `data` with `certChain[0]`'s public key using the same `algorithmName`. `false` → `AOException("El PKCS#1 de firma obtenido no se genero con el certificado indicado", INVALID_PKCS1_VALUE 200112)`; verification exception → `AOException(…, VERIFING_PKCS1_ERROR 200113)`. Without chain: warning only.
8. Returns the raw signature bytes (for RSA: PKCS#1 v1.5 signature over the digest of `data`; for ECDSA: Java's DER `SEQUENCE{r,s}`).

Other methods: all multisign/`getSignersStructure`/`getData`/`getSignInfo` → `UnsupportedOperationException`. `isSign` → always `false`. `isValidDataFile(d)` → `d != null && d.length > 0`. `getSignedName(name, in)`: name null → `"signature.p1"`; name ends with `.p1` (case-insensitive) → `name[:-3] + in + ".p1"`; else `name + in + ".p1"`.

### 3.3 `AOPkcs1TriPhaseSigner` (format `NONEtri`) — summary

Server-side-assisted raw PKCS#1. `sign()` → `triPhaseOperation(format="NONE", cop="sign", …)`:

* Requires non-null `extraParams` (else `IllegalArgumentException("Se necesitan parametros adicionales")`), key, non-empty chain, non-null data. `extraParams["serverUrl"]` must be a valid URL.
* `doc = Base64URLSafe(data)` (with `=` padding), `cert = Base64URLSafe(certChain[0].encoded)`.
* **Presign**: `POST <serverUrl>?op=pre&cop=sign&format=NONE&algo=<algorithm>&cert=<cert>&doc=<doc>` (URL query moved to body by the HTTP client, §9) with `SSLErrorProcessor(extraParams)`. Errors: `HttpError` → 300400; `SocketTimeoutException` → 401302; other `IOException` → 401300.
* Response body = Base64-URL-safe of a `TriphaseData` XML (§3.4); parse failure → 300401; zero signs → 300402. Take sign #0, `PRE` param (standard Base64) → bytes → `AOPkcs1Signer.sign(pre, algorithm, key, chain, extraParams)`; add `PK1 = Base64(pkcs1)`.
* **Postsign**: `POST <serverUrl>?op=post&cop=sign&format=NONE&algo=…&cert=…&doc=…&session=<Base64URLSafe(xml.toString())>` (no SSL processor). `HttpError` → 300404; timeout → 401402; IO → 401400.
* Response trimmed must start with `OK` else `AOException("La firma trifasica no ha finalizado correctamente: …", POSTSIGN_ERROR 300405)`; return `Base64URLSafeDecode(result.substring("OK NEWID=".length()))`; decode failure → 300407.
* `getSignedName(n, in)` = `n + (in or "") + ".p1"` (no null-check on `n` → `"null.p1"`). `isSign` → false; `isValidDataFile(d)` → `d != null`.

### 3.4 `TriphaseData` XML, `TriphaseDataSigner`, `TriphaseUtil`

Serialisation (`toString()`, byte-exact, values **not** XML-escaped):

```
<xml>\n <firmas[ format="FMT"]>\n
  <firma[ Id="ID"][ signid="SIGNID"]>\n
   <param n="KEY">VALUE</param>\n     (one per entry, unspecified order)
  </firma>\n
 </firmas>\n</xml>
```

Parsing: secure DOM (§8.8); first **element** child of the document element must be named `firmas` (case-insensitive) else `IllegalArgumentException("No se encontro el nodo 'firmas' en el XML proporcionado")`; optional attribute `format`. Each element child of `firmas` (any name) is a `TriSign` with optional attributes `Id`, `signid`; each element child of it is a param: key = attribute `n`, value = `textContent.trim()`. A `TriSign` without `Id` gets a random UUID. `getTriSign(id)`/`getTriSigns(id)` match `id` against `signid` or `Id`.

`TriphaseDataSigner.doSign(pkcs1Signer, algorithm, key, chain, data, extraParams)`: no signs → `AOException(PRESIGNS_NOT_FOUND 300402)`. For each sign: `PRE` missing → `AOException("El servidor no ha devuelto la prefirma numero i", 300401)`; Base64-decode (error → 300401); `algo = composeSignatureAlgorithmName(algorithm, key.getAlgorithm())`; `PK1 = Base64(sign(PRE))`; then remove `PRE` unless param `NEED_PRE` equals `true` (case-insensitive parseBoolean).

`TriphaseUtil.prepareCertChainParam(chain, extraParams)`: chain null/empty → `IllegalArgumentException`; if `extraParams == null` or `includeOnlySignningCertificate` (sic, double "n") is `true` → `Base64URLSafe(chain[0])`; else all certs Base64-URL-safe joined by `,`.

### 3.5 How `extraParams` reach a signer, and precedence rules

1. **Origin**:
   * Web protocol (`afirma://sign?...&properties=<B64>`): `AOUtil.base642Properties(value)` = replace `-`→`+`, `_`→`/`, standard Base64 decode, then `Properties.load(Reader UTF-8)` (§3.6). Load failure → empty Properties + warning (not an error).
   * Batch JSON/XML: per-signature and per-batch extraParams (batch spec).
   * Desktop UI: built from user preferences (`ExtraParamsHelper.loadExtraParamsForSigner`).
   * Applet/legacy JS: `ExtraParamsProcessor.convertToProperties(String)` = `Properties.load(new ByteArrayInputStream(entries.getBytes()))` — **GOTCHA**: `getBytes()` uses the platform charset (UTF-8 on Linux/macOS, cp1252 on Windows) and `load(InputStream)` decodes ISO-8859-1, so non-ASCII text is mangled unless written as `\uXXXX`. Exceptions → warning, partial result returned.
2. **Expansion** (§5): `ExtraParamsProcessor.expandProperties(params, data, format)` returns a **new** Properties (copy); the caller's object is not modified. Expanded values **override** user-supplied ones (logged as "La siguiente propiedad se ignora en favor del valor derivado de la politica establecida: <key>"). `expPolicy` itself is removed from the result.
3. **AUTO format** (`format=auto`): after resolving the signer (§4.4), `ExtraParamsProcessor.configAutoFormat(signer, data, params)` — only for `AOPDFSigner`: calls static `AOPDFSigner.configureRespectfulProperties(data, params)` which, if `signatureSubFilter` is absent, sets it to the subfilter of the first supported existing PDF signature (value after the leading `/`), so co-signatures match existing ones. Mutates `params` in place. Failure → warning.
4. **User confirmation loop** (`RuntimeConfigNeededException`, §10.3): the caller catches it and retries the same operation after mutating `extraParams`:
   * `RequestType.CONFIRM`: show `requestorText` message; on YES: if it is a `CustomRuntimeConfigNeededException` call `prepareOperationWithConfirmation(extraParams)`, else `extraParams[e.getParam()] = "true"`; retry. On NO → `AOCancelledOperationException`.
   * `RequestType.PASSWORD`: prompt; if `RuntimePasswordNeededException` → `configure(extraParams, password)`, else `extraParams[e.getParam()] = new String(password)`; retry. Cancel → `AOCancelledOperationException`.
   * If `e.isDenied()` (server already denied it) or extraParam `headless=true` → abort with the exception's error code.
5. **Binary values inside extraParams**: `ExtraParamsProcessor.loadByteArrayFromExtraParams(extraParams, name, secureMode)`:
   * missing → `IOException("La propiedad '<name>' no se encuentra en el extraParams")`;
   * if `!secureMode && 0 < len < 255 && !Base64.isBase64(value)` → treat as path/URL: `AOUtil.createURI(value)` + `AOUtil.loadFile(uri)` (errors → `IOException("El propiedad '<name>' no contiene una ruta valida a un recurso", cause)`);
   * else `Base64.decode(value)` (standard alphabet).
6. **Format-specific precedence** (e.g. `profile=baseline` making PAdES ignore `signatureSubFilter`) lives in the format specs.
7. **Non-string values (GOTCHA)**: `Properties` is a `Hashtable<Object,Object>`; afirma-simple puts the *object* `Boolean.TRUE` under key `confirmDifferentProfile` (desktop flow), and XAdES reads it with `Boolean.TRUE.equals(extraParams.get(...))`. Such entries are invisible to `getProperty` (returns `null`), are not serialised by `store`, cannot be supplied from the web (`confirmDifferentProfile=true` as text has **no** effect), and make `expandProperties` throw `NullPointerException` (it copies via `setProperty(k, getProperty(k))`). Rust: keep extraParams as `String→String` plus a separate typed "internal flags" set for this case.

### 3.6 Java `.properties` text format (needed for byte-exact interop)

Rust must implement `Properties.load` and `Properties.store` semantics:

* **load**: logical lines split on `\n`, `\r`, `\r\n`. Leading whitespace (space, `\t`, `\f`) skipped. Lines whose first non-white char is `#` or `!` are comments; blank lines ignored. A line ending in an **odd** number of `\` continues on the next line (leading whitespace of the continuation is dropped). The key ends at the first unescaped `=`, `:` or whitespace; then skip whitespace, at most one `=`/`:`, then whitespace; the rest is the value. Escapes in key and value: `\t \n \r \f`, `\uXXXX` (malformed → error `IllegalArgumentException("Malformed \\uxxxx encoding.")`), and `\<c>` → `<c>`. Duplicate keys: last wins. `load(InputStream)` = ISO-8859-1 bytes→chars; `load(Reader)` = given charset.
* **store(Writer, comments)** (used by `AOUtil.properties2Base64` with comment `""`): writes a `"#" + comments` line (here just `#`), then `"#" + new Date().toString()` line (e.g. `#Fri Oct 16 13:17:00 CEST 2026`), then `key=value` lines in hashtable order, line separator = platform `line.separator` (`\n` on Unix, `\r\n` on Windows). Escaping: in keys, space → `\ `; in values, a **leading** space → `\ `; `\`→`\\`, tab→`\t`, LF→`\n`, CR→`\r`, FF→`\f`; `=`, `:`, `#`, `!` → `\=`, `\:`, `\#`, `\!`. With a Writer, chars > 0x7E are **not** `\u`-escaped (they are with an OutputStream).
* `AOUtil.properties2Base64(p)` = Base64-**URL-safe** (with `=` padding) of the UTF-8 bytes of `store(...)`; `p == null` → `""`.
* `AOUtil.propertiesAsString(p)` = for each key: `key + "=" + value + "\n"` (no escaping, no comments); `null` → `""`.

---

## 4. `AOSignerFactory`

### 4.1 Registration table (exact order — it is also the detection order)

| # | Format name (key) | Implementation class (Java) | Used for detection (`isSign` probing) |
|---|---|---|---|
| 1 | `CAdES` | `es.gob.afirma.signers.cades.AOCAdESSigner` | **yes** |
| 2 | `CAdEStri` | `es.gob.afirma.signers.cadestri.client.AOCAdESTriPhaseSigner` | no |
| 3 | `CAdES-ASiC-S` | `es.gob.afirma.signers.cades.asic.AOCAdESASiCSSigner` | **yes** |
| 4 | `CAdES-ASiC-S-tri` | `es.gob.afirma.signers.cadestri.client.asic.AOCAdESASiCSTriPhaseSigner` | no |
| 5 | `CMS/PKCS#7` | `es.gob.afirma.signers.cms.AOCMSSigner` | **yes** |
| 6 | `FacturaE` | `es.gob.afirma.signers.xades.AOFacturaESigner` | **yes** |
| 7 | `Factura-e` | `…xades.AOFacturaESigner` | no |
| 8 | `FacturaEtri` | `es.gob.afirma.signers.xadestri.client.AOFacturaETriPhaseSigner` | no |
| 9 | `XAdES` | `es.gob.afirma.signers.xades.AOXAdESSigner` | **yes** |
| 10 | `XAdES Detached` | `…xades.AOXAdESSigner` | no |
| 11 | `XAdES Enveloped` | `…xades.AOXAdESSigner` | no |
| 12 | `XAdES Enveloping` | `…xades.AOXAdESSigner` | no |
| 13 | `XAdEStri` | `es.gob.afirma.signers.xadestri.client.AOXAdESTriPhaseSigner` | no |
| 14 | `XAdES-ASiC-S` | `es.gob.afirma.signers.xades.asic.AOXAdESASiCSSigner` | **yes** |
| 15 | `XAdES-ASiC-S-tri` | `es.gob.afirma.signers.xadestri.client.asic.AOXAdESASiCSTriPhaseSigner` | no |
| 16 | `XMLDSig` | `es.gob.afirma.signers.xmldsig.AOXMLDSigSigner` | **yes** |
| 17 | `XMLDSig Detached` | `…xmldsig.AOXMLDSigSigner` | no |
| 18 | `XMLDSig Enveloped` | `…xmldsig.AOXMLDSigSigner` | no |
| 19 | `XMLDSig Enveloping` | `…xmldsig.AOXMLDSigSigner` | no |
| 20 | `Adobe PDF` | `es.gob.afirma.signers.pades.AOPDFSigner` | no |
| 21 | `Adobe PDF TriPhase` | `es.gob.afirma.signers.padestri.client.AOPDFTriPhaseSigner` | no |
| 22 | `PAdES` | `…pades.AOPDFSigner` | **yes** |
| 23 | `PAdEStri` | `…padestri.client.AOPDFTriPhaseSigner` | no |
| 24 | `ODF (Open Document Format)` | `es.gob.afirma.signers.odf.AOODFSigner` | **yes** |
| 25 | `ODF` | `…odf.AOODFSigner` | no |
| 26 | `OOXML (Office Open XML)` | `es.gob.afirma.signers.ooxml.AOOOXMLSigner` | **yes** |
| 27 | `OOXML` | `…ooxml.AOOOXMLSigner` | no |
| 28 | `NONE` | `es.gob.afirma.core.signers.AOPkcs1Signer` | no |
| 29 | `NONEtri` | `es.gob.afirma.core.signers.AOPkcs1TriPhaseSigner` | no |

Not registered: `auto`, `PKCS1`, `PKCS#1`, `XAdES Externally Detached`, `XMLDSig Externally Detached`, `SOAP`.

### 4.2 API

* `getSigner(String signFormat)`: linear scan, **case-insensitive** match on column 2; first match wins. Unknown → log warning, return `null`. Instances are cached in a static map keyed by the **exact string passed** (so `"cades"` and `"CAdES"` produce two cached instances of the same class — harmless). Instantiation failure (module missing) → log severe, return `null`.
* `getSigner(byte[] signData)` and `getSigner(byte[] signData, Properties params)`: `signData == null` → `IllegalArgumentException("No se han indicado datos de firma")`. Iterate the table in order, skip rows whose column 4 is "no", lazily instantiate (failures skipped), return the **first** signer whose `isSign(signData)` (resp. `isSign(signData, params)`) is true; none → `null`. `IOException` from `isSign` propagates.
* `getSupportedFormats()`: all 29 names in table order.
* `getSignFormat(AOSigner)`: first row whose class equals the signer's class → that row's name. So `AOXAdESSigner`→`XAdES`, `AOPDFSigner`→`Adobe PDF` (**not** `PAdES`, row 20 precedes 22), `AOFacturaESigner`→`FacturaE`, `AOODFSigner`→`ODF (Open Document Format)`, `AOOOXMLSigner`→`OOXML (Office Open XML)`, `AOPDFTriPhaseSigner`→`Adobe PDF TriPhase`. Unknown → `null`.

### 4.3 Effective detection order and each `isSign` (summary; details in the format specs)

| Order | Format | `isSign(bytes)` returns true when… |
|---|---|---|
| 1 | CAdES | DER `ContentInfo` with contentType `1.2.840.113549.1.7.2` (signedData) and **every** SignerInfo has signed attributes containing `signingCertificate` (`1.2.840.113549.1.9.16.2.12`) or `signingCertificateV2` (`…2.47`). Any parse error → false. |
| 2 | CAdES-ASiC-S | **GOTCHA / bug**: extracts `META-INF/signature.p7s` from the ZIP, then calls `new AOCAdESASiCSSigner().isSign(p7s)` recursively (should have been `AOCAdESSigner`), which tries to unzip the p7s and fails ⇒ **always false** for real containers. CAdES-ASiC-S files are therefore never auto-detected (they end up `null` / "not a signature"). Decide whether to replicate. |
| 3 | CMS | signedData ContentInfo whose SignerInfos have signed attributes and **none** contains `signaturePolicyIdentifier` (`1.2.840.113549.1.9.16.2.15`). SignerInfo without signed attributes ⇒ NPE ⇒ false. (Plain CAdES-BES already matched row 1.) |
| 4 | FacturaE | parses as XML; root local name `Facturae` with child elements `FileHeader`, `Parties`, `Invoices`; **and** `AOXAdESSigner.isSign(document)` is true. |
| 5 | XAdES | parses as XML; collects the root if its local name is `Signature`, plus every `ds:Signature` (`http://www.w3.org/2000/09/xmldsig#`) descendant whose parent's local name is not `Timestamp`; non-empty and **every** collected node contains a descendant `QualifyingProperties` in one of `http://uri.etsi.org/01903#`, `http://uri.etsi.org/01903/v1.2.2#`, `http://uri.etsi.org/01903/v1.3.2#`, `http://uri.etsi.org/01903/v1.4.1#` (v1.1.1 is **not** accepted). |
| 6 | XAdES-ASiC-S | ZIP containing entry `META-INF/signatures.xml` whose content satisfies XAdES `isSign`. |
| 7 | XMLDSig | parses as XML and contains at least one `ds:Signature` (root or descendant). Note: any XAdES also satisfies this, which is why XAdES comes first. |
| 8 | PAdES | starts with `%PDF-`, length ≥ 70, iText can open it (password-protected PDFs count as PDF) **and** `getSignersStructure` lists ≥1 signature (or, if none, the PDF has unregistered signatures and the **JVM system property** `allowCosigningUnregisteredSignatures` equals `true`). |
| 9 | ODF | ZIP (`MimeHelper.isZipData`) whose `mimetype` entry is a supported ODF type **and** contains `META-INF/documentsignatures.xml`. |
| 10 | OOXML | ZIP with `[Content_Types].xml`, `_rels/.rels`, `docProps/app.xml`, `docProps/core.xml` (backslash variants accepted) **and** ≥1 OOXML signature part. |

Consequences: an unsigned PDF/XML/ODF/OOXML ⇒ `getSigner(bytes) == null`.

### 4.4 Format auto-selection for a given input (afirma-simple & protocol)

**A. Desktop app, file dropped/opened with no preset format** (`SignPanel.configureDataSigner(config, data)`), checks in this order:

| Step | Test (`es.gob.afirma.standalone.DataAnalizerUtil`) | FileType | Signer chosen |
|---|---|---|---|
| 1 | `isPDF` = `AOPDFSigner.isValidDataFile` (`%PDF-` header, ≥70 bytes, parsable) | `PDF` | `getSigner(pref defaultSignatureFormatPdf)` (default **`PAdES`**). If that signer is `AOPDFSigner` and `isSign(data)` (already signed) → operation `COSIGN`. |
| 2 | `isFacturae` = `AOFacturaESigner.isValidDataFile` | `FACTURAE` | pref `defaultSignatureFormatFacturae` (default **`FacturaE`**) |
| 3 | `isOOXML` = `AOOOXMLSigner.isValidDataFile` | `OOXML` | pref `defaultSignatureFormatOoxml` (default **`CAdES`**!) |
| 4 | `isODF` = `AOODFSigner.isValidDataFile` | `ODF` | pref `defaultSignatureFormatOdf` (default **`CAdES`**!) |
| 5 | `AOSignerFactory.getSigner(data)` non-null (an existing CAdES/CMS/XAdES/XMLDSig/… signature) | `SIGN_XADES` if `AOXAdESSigner`, else `SIGN_CADES` | that signer, operation `COSIGN` |
| 6 | `isXML` = `AOFileUtils.isXML` (well-formed, secure SAX) | `XML` | pref `defaultSignatureFormatXml` (default **`XAdES`**) |
| 7 | otherwise | `BINARY` | pref `defaultSignatureFormatBin` (default **`CAdES`**) |

Then: if `signer.isSign(data, extraParams)` → run validation of the existing signatures for display. Then extraParams are loaded from preferences for that signer and the internal flag `confirmDifferentProfile` = `Boolean.TRUE` object (not a string; see §3.5 item 7) is added.

When a format was preset (batch/"change format" flow, `configureDataSigner(newConfig, config, data)`): order is PDF → FacturaE → OOXML → ODF → **XML** → BINARY (no existing-signature step); the preset signer wins over the default; if the chosen signer `isSign(data)`, FileType is re-labelled `SIGN_CADES` (if `AOCAdESSigner`) or `SIGN_XADES` (if `AOXAdESSigner`) and validation info is computed.

Default preference values (file `afirma-ui-simple-configurator-common/src/main/resources/properties/preferences.properties`):
`defaultSignatureFormatPdf = PAdES`, `defaultSignatureFormatOoxml = CAdES`, `defaultSignatureFormatFacturae = FacturaE`, `defaultSignatureFormatOdf = CAdES`, `defaultSignatureFormatXml = XAdES`, `defaultSignatureFormatBin = CAdES`.

**B. Web protocol with `format=auto`** (`ProtocolInvocationLauncherUtil.identifyFormatFromData(data, op)`, also local batch):

* op `SIGN`: PDF → `PAdES`; else FacturaE (`isValidDataFile`) → `FacturaE`; else well-formed XML → `XAdES`; else → `CAdES`. (No OOXML/ODF special-casing: they become `CAdES`.)
* op `COSIGN`/`COUNTERSIGN`: `AOSignerFactory.getSignFormat(AOSignerFactory.getSigner(data))` (so a signed PDF yields `Adobe PDF`); `IOException` → `null`; `null` ⇒ error `SimpleErrorCode.Functional.CANT_IDENTIFY_SIGNATURE_FORMAT` (501009).
* The triphase server's `format=auto` uses `PreProcessorFactory.getPreProcessor(docBytes)` (server spec).

**C. Validator selection** — see §11.3.

`es.gob.afirma.signvalidation.DataAnalizerUtil` (validation module) duplicates these helpers and adds `isBinary` (= `AOCMSSigner.isValidDataFile` = non-null), `isSignedBinary` (CMS or CAdES `isSign`), `isSignedXML` (XAdES or XMLDSig), `isSignedPDF`, `isSignedFacturae`, `isSignedODF`, `isSignedOOXML`, `isCertificate(bytes)` (X.509 DER/PEM via CertificateFactory, else Base64 after replacing `%0A`→"", `%2F`→`/`, `%2B`→`+`, `%3D`→`=`; else `CertificateException("Los datos proporcionados no son un certificado X.509")`), the PDF shadow-attack helpers (§11.5) and `checkPDFForm`. All `is*` swallow exceptions → `false`.

---

## 5. `expPolicy` / `ExtraParamsProcessor` expansion

### 5.1 Source data (`afirma-core/src/main/resources/policy.properties`, verbatim)

```
FirmaAGE.policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9
FirmaAGE.policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf
FirmaAGE.policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1
FirmaAGE.policyIdentifierHash.XAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE.policyIdentifierHash.CAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE.policyIdentifierHash.PAdES=G7roucf600+f03r/o0bAOQ6WAs0=

FirmaAGE19.policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9
FirmaAGE19.policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf
FirmaAGE19.policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1
FirmaAGE19.policyIdentifierHash.XAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE19.policyIdentifierHash.CAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE19.policyIdentifierHash.PAdES=G7roucf600+f03r/o0bAOQ6WAs0=

FirmaAGE18.policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.8
FirmaAGE18.policyQualifier=https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf
FirmaAGE18.policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1
FirmaAGE18.policyIdentifierHash.XAdES=V8lVVNGDCPen6VELRD1Ja8HARFk=
FirmaAGE18.policyIdentifierHash.CAdES=7SxX3erFuH31TvAw9LZ70N7p1vA=
FirmaAGE18.policyIdentifierHash.PAdES=7SxX3erFuH31TvAw9LZ70N7p1vA=
```

No `policyDescription` entries exist (so it is never set). `FirmaAGE19` exists in the file but is **not** accepted by `expPolicy` (it is only read directly by afirma-simple's preferences panels and `SignDetails` to build "AGE 1.9" `AdESPolicy` presets).

### 5.2 Property lookup (`AdESPolicyPropertiesManager.getProperty(id, property, format)`)

Try keys in order, first present wins: `id.property.format`, `id.property`, `property.format`, `property`; none → `null`.

`setProperties(prop, policyId, format)`: first `isSupportedConfiguration` — if the hash (`getProperty(id, "policyIdentifierHash", fmt)`) is null/blank **and** the identifier is non-null → returns false and nothing is set (**GOTCHA**: the `!startsWith("http://") || !startsWith("https://")` test is always true). Otherwise, for each of `policyIdentifier`, `policyIdentifierHashAlgorithm`, `policyIdentifierHash`, `policyQualifier`, `policyDescription` (in that order) with a non-null value: overwrite `prop[key]` (warning if it already existed).

`isAgePolicyConfigurated(policyId)`: true iff some bundle key ending in `.policyIdentifier` has value equal to `policyId` (i.e. `urn:oid:2.16.724.1.3.1.1.2.1.9` or `…1.8`). Used by `XAdESCoSigner`.

### 5.3 Expansion algorithm (`expandProperties(params, signedData, format)`)

```
p = copy(params)
if "expPolicy" not in p: return p
name = p["expPolicy"]
if name not in {"FirmaAGE", "FirmaAGE18"} (case-sensitive):
    throw SignaturePolicyIncompatibilityException("No se soporta la expansion de atributos para la politica: " + name)
nf = normalizeFormat(format)        # GOTCHA: format == null -> NullPointerException
if nf == "CAdES" and name in {FirmaAGE, FirmaAGE18}: cades(name, p, signedData)
elif nf == "XAdES" and name in {FirmaAGE, FirmaAGE18}: xades(name, p)
elif nf == "PAdES" and name == "FirmaAGE": pades(name, p)
else: throw SignaturePolicyIncompatibilityException(String.format("El formato de firma %1s no esta soportado por la politica %2s", format, name))
remove p["expPolicy"]; return p
```

`normalizeFormat(format)` (case-insensitive):
* `CAdES`, `CAdEStri` → `CAdES` (NOT `CAdES-ASiC-S*`).
* `XAdES`, `XAdEStri`, or anything starting with `"xades "` (e.g. `XAdES Detached`) → `XAdES` (NOT `XAdES-ASiC-S*`).
* `Adobe PDF`, `PAdES`, `Adobe PDF TriPhase`, `PAdEStri` → `PAdES`.
* else unchanged (so `auto`, `FacturaE`, `CMS/PKCS#7`, `ODF`, ASiC… ⇒ incompatibility exception).

Per-format steps (applied to `p`, before the policy attributes):

| Format | Step |
|---|---|
| CAdES | If `mode` absent **and** `signedData != null`: `mode = implicit` if `signedData.length < 1048576` else `explicit`. Then `profile = advanced` (warning if it was `baseline`, case-insensitive). Then `setProperties(p, name, "CAdES")`. |
| XAdES | If `format` (the extraParam!) is not `XAdES Detached`/`XAdES Enveloped` (case-insensitive) → set `format = XAdES Detached` (warning if it was non-null). Then `profile = advanced` (warning if `baseline`). Then `setProperties(p, name, "XAdES")`. |
| PAdES (FirmaAGE only) | If `signatureSubFilter` present and ≠ `ETSI.CAdES.detached` (case-sensitive) → throw `SignaturePolicyIncompatibilityException("En PAdES con politica firma AGE debe usarse siempre el filtro 'ETSI.CAdES.detached'")`. Set `signatureSubFilter = ETSI.CAdES.detached`. Then `setProperties(p, name, "PAdES")`. (Note: `profile` is NOT forced for PAdES.) |

### 5.4 Resulting expansion tables

| `expPolicy` | Format family | Keys set (override) |
|---|---|---|
| `FirmaAGE` | CAdES | `mode`=implicit/explicit (only if absent and data given; <1 MiB ⇒ implicit), `profile=advanced`, `policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9`, `policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1`, `policyIdentifierHash=G7roucf600+f03r/o0bAOQ6WAs0=`, `policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` |
| `FirmaAGE` | XAdES | `format=XAdES Detached` unless already `XAdES Detached`/`XAdES Enveloped`, `profile=advanced`, `policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9`, `policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1`, `policyIdentifierHash=G7roucf600+f03r/o0bAOQ6WAs0=`, `policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` |
| `FirmaAGE` | PAdES | `signatureSubFilter=ETSI.CAdES.detached`, `policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9`, `policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1`, `policyIdentifierHash=G7roucf600+f03r/o0bAOQ6WAs0=`, `policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` |
| `FirmaAGE18` | CAdES | `mode` rule as above, `profile=advanced`, `policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.8`, `policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1`, `policyIdentifierHash=7SxX3erFuH31TvAw9LZ70N7p1vA=`, `policyQualifier=https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf` |
| `FirmaAGE18` | XAdES | `format` rule as above, `profile=advanced`, `policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.8`, `policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1`, `policyIdentifierHash=V8lVVNGDCPen6VELRD1Ja8HARFk=`, `policyQualifier=…/politica_firma_AGE_v1_8.pdf` (same URL as above) |
| `FirmaAGE18` | PAdES | **not supported** → `SignaturePolicyIncompatibilityException` (code 501008) |
| any other value (incl. `FirmaAGE19`) | any | `SignaturePolicyIncompatibilityException` |
| `FirmaAGE`/`FirmaAGE18` | any other format (FacturaE, CMS, ODF, OOXML, ASiC, NONE, auto…) | `SignaturePolicyIncompatibilityException` |

Decoded hash bytes (hex, 20-byte SHA-1 values) for test vectors: `G7roucf600+f03r/o0bAOQ6WAs0=` = `1bbae8b9c7fad34f9fd37affa346c0390e9602cd`; `V8lVVNGDCPen6VELRD1Ja8HARFk=` = `57c95554d18308f7a7e9510b443d496bc1c04459`; `7SxX3erFuH31TvAw9LZ70N7p1vA=` = `ed2c57ddeac5b87df54ef030f4b67bd0dee9d6f0`. Always emit the Base64 strings verbatim.

Callers: `UrlParametersToSign/ToSignAndSave.expandExtraParams()` (format = URL `format` param, data = URL data), afirma-simple `ProtocolInvocationLauncherSign/SignAndSave`, triphase server `SignatureService` and batch `JSONSingleSign{Pre,Post}Processor` (format = enum `name()`), MiniApplet.

### 5.5 `AdESPolicy` (value object consumed by signers)

`new AdESPolicy(identifier, identifierHash, identifierHashAlgorithm, qualifier)` (`predefined=false`), or `(predefined, …)`:

* `identifier` null/empty → `IllegalArgumentException("El identificador de politica no puede ser nulo ni vacio")`.
* If `identifierHash` is null or `"0"`: hashAlgorithm = `identifierHashAlgorithm == null ? "SHA-512" : getDigestAlgorithmName(identifierHashAlgorithm)`; **download** `identifier` as a URL (Java `new URL(identifier).openStream()`, no proxy/SSL customisation, no timeouts) and set hash = Base64(digest(content)). Any failure → `IllegalArgumentException("Si no se especifica la huella digital de la politica es necesario que el identificador sea una URL accesible universalmente: …")`.
* Else: `identifierHashAlgorithm` null/empty → `IllegalArgumentException("Si se indica la huella digital del identificador de politica es obligatorio indicar tambien el algoritmo")`; `!Base64.isBase64(hash)` → `IllegalArgumentException("La huella digital de la politica debe estar en formato Base64")`; store hash as given and algorithm **normalised** via `getDigestAlgorithmName` (so `http://www.w3.org/2000/09/xmldsig#sha1` → `SHA1`).
* `qualifier` non-empty must parse as a URL else `IllegalArgumentException("El calificador de la politica debe ser una URL valida")`.
* `buildAdESPolicy(extraParams)`: null → IAE; `policyIdentifier` absent → `null`; else construct from keys `policyIdentifier`, `policyIdentifierHash`, `policyIdentifierHashAlgorithm`, `policyQualifier`.
* `asExtraParams()`: inverse (only non-null values; note the hash algorithm is now the normalised name).
* `equals`: identifier, hash and hashAlgorithm equal (qualifier ignored); `hashCode` = identifier's.

---

## 6. File / data type detection

### 6.1 `MimeHelper(byte[] data)`

Construction (`data == null` → `IllegalArgumentException("No se han indicado los datos que se desean analizar")`) runs **JMimeMagic** (`net.sf.jmimemagic.Magic.getMagicMatch(data)`, external lib `es.gob.afirma.lib:afirma-lib-jmimemagic:0.0.10`, loaded by reflection) and stores its `mimeType`, `extension`, `description` (each `"???"` → `null`). If the library is missing or no match is found, all three are `null` (only logged).

JMimeMagic is a magic-number matcher driven by its bundled `magic.xml` (not in this repo). **Rust parity recommendation**: implement a magic table that at least returns: `application/pdf` (`%PDF`), `application/zip` (`PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`), `text/xml` (XML declaration / `<`), `application/msword` (OLE2 `D0 CF 11 E0 A1 B1 1A E1`), common images (`image/jpeg` FF D8 FF, `image/png` 89 50 4E 47, `image/gif` GIF8, `image/tiff` II*\0 / MM\0*), `text/html`, `application/postscript` (`%!`), RTF (`{\rtf` → `text/rtf`), etc., with the extension/description JMimeMagic would give (`pdf`/"Adobe PDF document", `zip`, `xml`, `doc`, `jpg`, `png`, `gif`, `tif`, …). Only `application/zip`, `application/msword`, `text/xml` and "unknown" drive core logic; the rest only affect the default data file name inside ASiC containers (`dataobject.<ext>`), suggested output names and UI descriptions.

`getMimeType()` (memoised once "verified"):

1. If the magic result is `null` or `text/xml`: if `AOFileUtils.isXML(data)` → `text/xml` (verified); else treat as `null`.
2. If the (possibly reset) type is `application/zip` or `application/msword` → `OfficeAnalizer.getMimeType(data)` (verified).
3. If still `null` → `application/octet-stream` (verified).
4. Else return the magic type.

`getExtension()`: `t = getMimeType()`; `t == application/octet-stream` → keep the JMimeMagic extension (possibly `null`); `t == text/xml` → `xml`; else if `OfficeAnalizer.FILE_EXTENSIONS[t]` exists → that; else keep the JMimeMagic extension. Returned **without dot**.

`getDescription()`: `t == text/xml` → `Documento XML`; `t` not default and in `OfficeAnalizer.FILE_DESCRIPTIONS` → that; else magic description, else `binary`.

`isZipData()`: **GOTCHA** — since `mimeInfo` is always non-null after construction, this returns `magicMimeType == "application/zip"` and never reaches the byte check below (dead code): first 4 bytes `50 4B 03 04`, `50 4B 05 06` or `50 4B 07 08`. Rust: implement the byte check (equivalent for real ZIPs, and robust when the magic table lacks ZIP). Note that `AOODFSigner.isValidDataFile` depends on this.

`transformMimeTypeToOid(mime)` / `transformOidToMimeType(oid)`: lookups in `resources/mimetypes_oids.properties` (reverse map built by inverting; on duplicate values the last inverted wins). `null` input or unknown → `1.2.840.113549.1.7.1` / `application/octet-stream`. Table (verbatim):

| OID | MIME type |
|---|---|
| `1.2.840.113549.1.7.1` | `data` (sic — not a MIME type) |
| `1.2.840.10003.5.109.1` | `application/pdf` |
| `1.2.840.10003.5.109.2` | `application/postscript` |
| `1.2.840.10003.5.109.3` | `text/html` |
| `1.2.840.10003.5.109.4` | `image/tiff` |
| `1.2.840.10003.5.109.5` | `image/gif` |
| `1.2.840.10003.5.109.6` | `image/jpeg` |
| `1.2.840.10003.5.109.7` | `image/png` |
| `1.2.840.10003.5.109.8` | `video/mpeg` |
| `1.2.840.10003.5.109.9` | `text/sgml` |
| `1.2.840.10003.5.109.10` | `text/xml` |
| `1.2.840.113556.4.2` | `application/msword` |
| `1.2.840.113556.4.3` | `application/vnd.ms-excel` |
| `1.2.840.113556.4.4` | `application/vnd.ms-project` |
| `1.2.840.113556.4.5` | `application/vnd.ms-powerpoint` |
| `1.2.840.113556.4.6` | `application/vnd.ms-works` |

(Used by CAdES/XAdES signers for `contentHint`/`DataObjectFormat`; e.g. `transformOidToMimeType("1.2.840.113549.1.7.1")` returns `data`.)

### 6.2 `OfficeAnalizer`

`getMimeType(byte[] data)` (package-private, called from `MimeHelper`):

1. `data.length >= 1_000_000_000` → `IOException("El archivo tiene un tamano superior al permitido.")`.
2. Write to a temp file (`afirma*.tmp`), open as ZIP:
   * **ODF** if all entries exist: `mimetype`, `content.xml`, `meta.xml`, `settings.xml`, `styles.xml`, `META-INF/manifest.xml` → read `mimetype` entry (whole content, platform charset, **no trim**) and accept only if in `ODF_MIMETYPES`.
   * else **OOXML** if entries `[Content_Types].xml`, `_rels/.rels`, `docProps/app.xml`, `docProps/core.xml` exist → parse `[Content_Types].xml` (secure DOM), root must be `Types` (case-insensitive), for each child `Override` (case-insensitive) take attribute `ContentType`, strip from the **last** `.` onwards (`…document.main+xml` → `…document`), return the first value found in `OOXML_MIMETYPES`.
   * else `getMimeTypeOffice97(data)`.
   * If the ZIP opened but nothing matched → `application/zip`. If it is not a ZIP (`ZipException`) → nothing.
3. Delete temp file. If still null → `getMimeTypeOffice97(data)`; still null → `application/octect-stream` (typo kept).

`getMimeTypeOffice97(data)`: `s = new String(data)` (platform charset); substring tests in order: `Microsoft Excel` → `application/vnd.ms-excel`; `Microsoft Office Word` → `application/msword`; `Microsoft Office PowerPoint` → `application/vnd.ms-powerpoint`; `Microsoft Project` → `application/vnd.ms-project`; `Microsoft Visio` → `application/vnd.visio`; else null.

`OOXML_MIMETYPES` (17): `application/vnd.ms-word.document.macroEnabled.12`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `application/vnd.ms-word.template.macroEnabled.12`, `application/vnd.openxmlformats-officedocument.wordprocessingml.template`, `application/vnd.ms-powerpoint.template.macroEnabled.12`, `application/vnd.openxmlformats-officedocument.presentationml.template`, `application/vnd.ms-powerpoint.addin.macroEnabled.12`, `application/vnd.ms-powerpoint.slideshow.macroEnabled.12`, `application/vnd.openxmlformats-officedocument.presentationml.slideshow`, `application/vnd.ms-powerpoint.presentation.macroEnabled.12`, `application/vnd.openxmlformats-officedocument.presentationml.presentation`, `application/vnd.ms-excel.addin.macroEnabled.12`, `application/vnd.ms-excel.sheet.binary.macroEnabled.12`, `application/vnd.ms-excel.sheet.macroEnabled.12`, `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `application/vnd.ms-excel.template.macroEnabled.12`, `application/vnd.openxmlformats-officedocument.spreadsheetml.template`.

`ODF_MIMETYPES` (15): `application/vnd.oasis.opendocument.text`, `…text-template`, `…text-web`, `…text-master`, `…graphics`, `…graphics-template`, `…presentation`, `…presentation-template`, `…spreadsheet`, `…spreadsheet-template`, `…chart`, `…formula`, `…database`, `…image` (all `application/vnd.oasis.opendocument.*`), and `application/vnd.openofficeorg.extension`.

`FILE_EXTENSIONS` / `FILE_DESCRIPTIONS`:

| MIME | ext | description |
|---|---|---|
| `application/zip` | `zip` | `Archivo zip` |
| `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | `docx` | `Documento de texto` |
| `application/vnd.openxmlformats-officedocument.presentationml.presentation` | `pptx` | `Presentación` |
| `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `xlsx` | `Hoja de cálculo` |
| `application/vnd.oasis.opendocument.text` | `odt` | `Documento de texto` |
| `application/vnd.oasis.opendocument.presentation` | `odp` | `Presentación` |
| `application/vnd.oasis.opendocument.spreadsheet` | `ods` | `Hoja de cálculo` |
| `application/vnd.oasis.opendocument.graphics` | `odg` | `Gráfico` |
| `application/vnd.oasis.opendocument.chart` | `odc` | `Diagrama` |
| `application/vnd.oasis.opendocument.formula` | `odf` | `Fórmula` |
| `application/vnd.oasis.opendocument.database` | `odb` | `Base de datos` |
| `application/vnd.oasis.opendocument.image` | `odi` | `Imagen` |
| `application/vnd.oasis.opendocument.text-master` | `odm` | `Plantilla de documento` |
| `application/msword` | `doc` | `Documento de texto` |
| `application/vnd.ms-powerpoint` | `ppt` | `Presentación` |
| `application/vnd.ms-excel` | `xls` | `Hoja de cálculo` |
| `application/vnd.ms-project` | `mpp` | `Planificaci&oacute;n de proyecto` (sic, HTML entity kept) |

Public helpers: `isOOXMLDocument(bytes)` (size check + ZIP + the 4 OOXML entries; any error → false) and `isODFDocument(bytes)` (size check + ZIP + the 6 ODF entries; **does not** check the `mimetype` value). `getOOXMLMimeType(InputStream)` is public.

### 6.3 `AOFileUtils.isXML(byte[])`

True iff the bytes parse completely with the secure SAX parser (§8.8: namespace-aware, non-validating, DOCTYPE **forbidden**, external entities off). Any exception → false. Consequence: XML documents with a `<!DOCTYPE …>` are **not** XML for AutoFirma (they become "binary" → CAdES).

### 6.4 Summary of how a file type is decided

There is **no extension-based detection** in core: everything is content-based (the file name is only used for output naming and UI filters). Order of decisions in the app: PDF header → FacturaE structure → OOXML structure → ODF structure → existing signature (factory probing) → well-formed XML → binary (§4.4).

---

## 7. Base64 and `AOUtil`

### 7.1 `es.gob.afirma.core.misc.Base64` (iharder 2.3.7 derivative)

* `encode(byte[])`: standard alphabet `A–Z a–z 0–9 + /`, `=` padding, **no line breaks**. Output ASCII.
* `encode(byte[], urlSafe=true)`: alphabet with `-` `_` instead of `+` `/`, **still `=`-padded**.
* `decode(String)` = `decode(str.getBytes(US-ASCII), 0, len, false)`; `decode(String, urlSafe)`; `decode(byte[], off, len, urlSafe)`:
  * `len == 0` → empty array; `len < 4` (raw length, counting whitespace) → `IllegalArgumentException("Base64-encoded string must have at least four characters, but length specified was N")`.
  * Whitespace bytes `\t \n \r space` are skipped. Any other byte not in the selected alphabet (and not `=`) → `IOException("Bad Base64 input character decimal %d in array position %d")`. Hence the **standard decoder rejects `-`/`_`** and the URL-safe decoder rejects `+`/`/`. Non-ASCII chars become `?` via US-ASCII encoding → error.
  * Bytes are grouped in quartets; when a quartet completes and its last char is `=`, decoding **stops** (rest ignored). A trailing incomplete quartet (1–3 chars) is **silently dropped** (no error). `=` at quartet positions 0/1 produces garbage rather than an error (edge case; mimic only if testing against hostile input is required).
* `isBase64(byte[])` / `isBase64(String)`: every char ∈ `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=_-\t\n+/0123456789\r~` (note: `~` and both alphabets accepted), `=` allowed only at index ≥ `len-2`, and the number of chars excluding `\n`/`\r` (tabs **are** counted) is a multiple of 4. Empty input → `true`. **GOTCHA**: `"...==\n"` → false (the `=` is at `len-3`).
* Common caller idioms: (a) URL-safe input decoded with the standard decoder after `replace('-', '+').replace('_', '/')` (`AOUtil.base642Properties`, `DataDownloader`); (b) `Base64.decode(bytes, 0, len, true)` (triphase responses).

### 7.2 `AOUtil`

* `createURI(String file)`: null/empty → `IllegalArgumentException("No se puede crear una URI a partir de un nulo")`; trimmed empty → `IllegalArgumentException("La URI no puede ser una cadena vacia")`. Replace `\`→`/`, then escape: space→`%20`, `<`→`%3C`, `>`→`%3E`, `"`→`%22`, `{`→`%7B`, `}`→`%7D`, `|`→`%7C`, `^`→`%5E`, `[`→`%5B`, `]`→`%5D`, `` ` ``→`%60`. Parse as `java.net.URI`. If scheme ∈ {`http`,`https`,`file`,`urn`} (case-sensitive) → return. If scheme is null → replace `#`→`%23` and recurse with `"file://" + filename`. If scheme is a single letter (Windows drive) → same. Else `URISyntaxException(filename, "Tipo de URI no soportado")`. (Relative paths become `file://relative/path`; see `loadFile`.)
* `loadFile(URI)`: scheme `file` → path = the **percent-decoded** scheme-specific part (Java `getSchemeSpecificPart()`), with one leading `//` removed (so `createURI("/a b.pdf")` = `file:///a%20b.pdf` → opens `/a b.pdf`; `createURI("a.pdf")` = `file://a.pdf` → opens the relative path `a.pdf`; `createURI("C:\\x\\y.pdf")` = `file://C:/x/y.pdf` → opens `C:/x/y.pdf`). Other schemes → `uri.toURL().openStream()` fully read into memory (no proxy/timeout customisation beyond JVM defaults).
* `getDataFromInputStream(is)`: read to end with a 4096-byte buffer; `null` → empty array; does not close.
* `getCN(X509Certificate)` → `getCN(cert.getSubjectX500Principal().toString())`. `getCN(String principal)`: value of `cn`, else of `ou`, else (if there is an `=`) the value of the first attribute (`principal.substring(0, indexOf('='))` used as RDN name), else the whole string. `null` → `null`.
  * The principal string is **Java `X500Principal.toString()`** format: RDNs in **reverse DER order** (for a typical cert encoded `C, O, OU, CN` it prints `CN=…, OU=…, O=…, C=ES`), separated by `", "`, multi-valued RDNs joined with `" + "`. Attribute keywords (Java `sun.security.x509.AVA`, DEFAULT style): `CN, C, L, ST, O, OU, T, IP, STREET, DC, DNQ, SURNAME, GIVENNAME, INITIALS, GENERATION, EMAILADDRESS, UID, SERIALNUMBER`; other OIDs as `OID.<dotted>=…`; values containing special characters (`,+=<>#;"`, leading/trailing spaces, …) are double-quoted. Rust must render DNs exactly like this for CN extraction and for UI text — build test vectors from real Java output for Spanish certificates (FNMT/DNIe subjects with `SERIALNUMBER`, `SURNAME`, `GIVENNAME`, `OID.2.5.4.97`).
* `getRDNvalueFromLdapName(rdn, principal)` (case-insensitive name search): find occurrence of `rdn` (lower-cased) in the lower-cased principal at index 0 or preceded by `,` or space; skip spaces; require `=` (else keep searching from the next position); skip spaces; at end → `""`; next char `,` → `""`; if `"` → content up to the next `"` (or to end), `""` if empty; else up to the next `,` (or end), **trimmed**. Not found → `null`. Escaped commas (`\,`) are not handled (value truncated).
* `getOUS(principal)`: repeatedly takes `ou` values, removing `OU=<v>` / `ou=<v>` occurrences (and quoted forms) to find the next → `String[]`.
* `isPseudonymCert(cert)`: `getRDNvalueFromLdapName("2.5.4.65", subject.getName(RFC2253)) != null` (pseudonym attribute; RFC 2253 prints unknown OIDs as `2.5.4.65=#…`).
* `hexify(bytes, boolean sep)`: uppercase hex; with `sep`: `-` between bytes and `\n` instead of `-` after every 16th byte (no trailing newline). `null` → `"null"`. `hexify(bytes, String sep)`: separator between every byte.
* `split(text, sep)`: literal (non-regex) split keeping empty fields, including a trailing empty field (`"a$b$"` → `["a","b",""]`).
* `properties2Base64`, `base642Properties`, `propertiesAsString`: §3.6 / §3.5.
* `isJava9orNewer()`, `isOnlyNumber(s)` (`^[0-9]+$`), `loadNativeLibrary`, `copyFile`: Java-runtime helpers (not needed in Rust except `isOnlyNumber`).

---

## 8. Platform & infrastructure utilities

### 8.1 `Platform`

* `OS` enum: `WINDOWS` (os.name contains `indows`), `LINUX` (contains `inux`; `ANDROID` if `java.vm.name == Dalvik`), `SOLARIS` (`SunOS` or `olaris`), `MACOSX` (starts with `Mac OS X`), else `OTHER`. Cached.
* `MACHINE`: `aarch64`/`arm64*`→`ARM64`; `mips64`→`MIPS64`; `mips`→`MIPS32`; `x86_64`/`amd64*`→`AMD64`; `x86`→`X86`; else `OTHER` (**GOTCHA**: `i386`/`i686` → `OTHER`, ARM32 never returned).
* `BROWSER getBrowser(userAgent)` (lower-cased substring, in order): `msie`→IE, `firefox`, `chrome`, `safari`, `opera`, else OTHER; null → OTHER.
* `getJavaArch()` = `sun.arch.data.model` or `com.ibm.vm.bitmode` (`"32"`/`"64"`). Rust: pointer width.
* `getUserHome()` = `user.home` (no trailing separator).
* `isUnixSystem(os)`: LINUX, MACOSX, SOLARIS.
* `getSystemRoot()`: non-Windows → `/`; Windows → system property `SystemRoot`, else `C:\WINDOWS` if `C:\WINDOWS\system32` exists, else `File.separator`.
* `getSystemLibDir()`: Windows → `<root>\System32`, or `<root>\SysWOW64` if the JVM is 32-bit and it exists; Unix → `/usr/lib<arch>` (e.g. `/usr/lib64`) if it exists, else `/usr/lib`.

### 8.2 `LoggerUtil`

* `getCleanUserHomePath(path)` = `path.replace(userHome, "USERHOME")` (plain substring replace, all occurrences).
* `getTrimStr(s)` / `getTrimObject(o)` / `getTrimBytes(b)`: if system property `allow.extended.logs` is not `true` and length ≥ 200 (bytes: > 200) → first 200 chars + `"..."`. (`getTrimBytes(null)` throws NPE.) Used in log messages and in `HttpError` messages.

### 8.3 `LogManager.install(App app[, String logDir])`

Adds a file handler to logger `"es.gob"`: path `<home>/.afirma/<APP>.afirma.log.xml` or `<logDir>/<APP>.afirma.log.xml` (`\`→`/`, `%h`→user home), creating directories. Size limit 2 MiB, 1 generation, truncate on start, Java `XMLFormatter` output. `getLogFile()` closes/reopens the handler and returns the file content (used by "send log" features).

### 8.4 `AOFileUtils`

* `createTempFile(data)`: temp file with prefix `afirma` (Java adds `.tmp`).
* `pathLengthShortener(path, limit)`: if `len ≤ limit` → unchanged. Else build a `limit`-char array: copy the path's tail backwards until a `/` or `\` or `limit` chars; `free = limit - copied`; if `free < 3` → put `...` in positions 0..2 (overwriting); else copy the first `free-3` chars of the path and then `...` (positions `free-3 .. free-1`). Result: `"C:\Users\foo\...\file.txt"`-style.
* `isXML(data)`: §6.3.
* `setAllPermissions(file)`: rw-x for everyone (+ ACL entries on Windows + POSIX 0777). Best effort, never throws.

### 8.5 `BoundedBufferedReader`

`readLine()` with limits (default 4096 lines, 4096 chars/line): exceeding the line count → `IOException("BoundedBufferedReader - Line read limit has been reached.")`; overly long lines are split at the limit (the rest is returned by the next call, after skipping a following CR/LF/CRLF). Line terminators: CR, LF, CRLF.

### 8.6 `KeyUsage` (`es.gob.afirma.core.keystores`)

9-bit `Boolean[]` (digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly), `null` = "don't care". Presets: `SIGN` (nonRepudiation=true), `AUTH` (digitalSignature=true), `CYPH` (dataEncipherment=true). From a cert: `cert.getKeyUsage()` (absent → `usage=null`; length ≠ 9 → `IllegalArgumentException`). `includes(ku)`: every non-null bit of `ku` equals ours. `toString()` → CoreMessages `KeyUsage.N` (es: 0 `Desconocido`, 1 `Firma, autenticación y cifrado`, 2 `Autenticación y cifrado`, 3 `Firma y cifrado` (unreachable), 4 `Firma y autenticación`, 5 `Autenticación`, 6 `Firma`, 7 `Cifrado`, 8 `Otros`) evaluated in that order. **GOTCHA**: the bit comparison uses Java `Boolean` object identity (`!=`), which works because `Boolean.valueOf` is canonical.

### 8.7 `CoreMessages` / `LanguageManager`

Bundle `resources/coremessages/coremessages_<locale>.properties` for `es_ES, ca_ES, gl_ES, eu_ES, va_ES, en_US` (`AFIRMA_DEFAULT_LOCALES`, es_ES first). Keys (es): `AutofirmaTrustStore.0` "No se ha podido cargar el almacén de claves de Autofirma. Es posible que esté corrupto. ¿Desea crearlo de nuevo?", `AutofirmaTrustStore.1` "Carga del almacén de confianza", `SSLRequestPermissionDialog.1` "Advertencia", `SSLRequestPermissionDialog.2` `El certificado SSL del dominio "%0" no es de confianza. ¿Desea importarlo en su almacén de confianza?`, `KeyUsage.0..8`. Missing key → `"!" + key + "!"`. `getString(key, text)` replaces `%0`; `getString(key, String[])` replaces `%0..%n`.
`LanguageManager`: user-imported language packs (ZIP with `metadata.info` lines `key=value`: `locale`, `language.name`, `fallback.locale` like `es_ES`) unzipped under `<langDir>/<locale>/`; failures → `AOException(new ErrorCode("230001"))` (no description). Help dir `<home>/.afirma/Autofirma/help`. Full details belong to the UI spec.

### 8.8 Secure XML parsing (`SecureXmlBuilder`, `SecureXmlTransformer`)

Every XML parse in core (TriphaseData, OOXML content types, `isXML`, validation) uses:

* DOM: secure-processing on; `accessExternalDTD/Schema/Stylesheet = ""`; `http://apache.org/xml/features/disallow-doctype-decl = true`; non-validating; **namespace-aware**.
* SAX: secure-processing; external general/parameter entities off; DOCTYPE disallowed; non-validating; namespace-aware.
* Transformer: secure-processing; no external DTD/stylesheet.

Rust: use a parser configuration that rejects any DOCTYPE (error ⇒ "not XML") and never resolves external entities. (Signers in other modules use their own `Utils.getNewDocumentBuilder()`; see format specs.)

---

## 9. HTTP client (`es.gob.afirma.core.misc.http`)

### 9.1 Interfaces

* `UrlHttpMethod`: `GET`, `POST`, `PUT`.
* `UrlHttpManager.readUrl(...)` overloads all funnel to `readUrl(url, connectTimeout, method, requestHeaders: Properties, errorProcessor, sslConfig)`; the `(url, timeout, contentType, accept, method, …)` overloads build headers `Content-Type` / `Accept` from non-null args. Plus `setReadTimeout(int)` / `getReadTimeout()` (instance state, default `-1`).
* `UrlHttpManagerFactory.install(manager)` / `getInstalledManager()` (lazy singleton `UrlHttpManagerImpl`). **GOTCHA**: the read timeout is set on this shared singleton (`ConnectionConfig.apply`) and persists for later calls in the process.
* `ConnectionConfig { readTimeout = -1 (DEFAULT_TIMEOUT); defaultConnection }`; `apply(manager)` sets the read timeout if ≠ -1. Used by the protocol's `servicetimeout` URL parameter for triphase signers.
* `SSLConfig { HostnameVerifier; SSLSocketFactory }` — per-connection TLS override.
* `HttpErrorProcessor.processHttpError(IOException cause, UrlHttpManager mgr, url, timeout, method, requestHeaders) -> byte[]` — recovery hook (only implementation: `SSLErrorProcessor`).
* `HttpError extends IOException`: `responseCode`, `responseDescription` (status reason), `errorStreamBytes` (response body). Message: `"Error HTTP con codigo  <code>[, cuerpo '<trimmed body>'] y descripcion '<reason>' para la direccion: <trimmed url>"` (two spaces after "codigo").

### 9.2 `UrlHttpManagerImpl.readUrl` — exact behaviour

1. `url == null` → `IllegalArgumentException("La URL a leer no puede ser nula")`.
2. **Credentials in URL**: parsed with `URLName` (javax.mail-style: `proto://[user[:pass]@]host[:port]/file[#ref]`, user/pass percent-decoded with `+`→space, decoded as ISO-8859-1 bytes then re-decoded with the platform charset). If user or password present: `auth = Base64(user + ":" + pass)` (or just user / just pass) using platform-charset bytes; URL rebuilt as `proto://host[:port]/file` (the `#ref` is dropped).
3. **POST/PUT**: split the URL on `?` (Java `StringTokenizer`: first token = target URL, **only the second token** is the body — a second `?` in the query truncates the body; **GOTCHA**). The body is the raw query string, UTF-8 encoded, sent with `Content-Length`. No explicit `Content-Type` is set ⇒ Java sends `Content-Type: application/x-www-form-urlencoded` (HttpURLConnection default when writing a body). GET: URL used as-is.
4. **Proxy**: if OS is Android or the host resolves to a loopback address (`InetAddress.getByName(host).isLoopbackAddress()`; DNS failure ⇒ not local) → direct connection (`Proxy.NO_PROXY`); otherwise the JVM default `ProxySelector` (configured by afirma-simple `ProxyUtil`: SYSTEM via proxy-vole OS/browser detection, CUSTOM via `http(s).proxyHost/Port`, `*.nonProxyHosts`, global `Authenticator` with decrypted credentials, or NONE).
5. **TLS** (only for `https`):
   * `disableChecks = (sslConfig == null) && Boolean.parseBoolean(System.getProperty("disableSslChecks", "false"))`.
   * `secureDomain = host matches an entry of System property secureDomainsList` (comma-separated, entries **not trimmed**): `*x*` → host contains `x`; `*x` → host ends with `x`; `x*` → host starts with `x`; `x` → host equals `x` (all case-sensitive).
   * If `disableChecks || secureDomain` → trust-all `SSLContext("SSL")` (no client key manager) + hostname verifier accepting everything (errors only logged). **Note**: a matching secure domain disables checks even when an `sslConfig` is supplied.
   * else if `sslConfig != null` → apply its socket factory / hostname verifier (each if non-null).
   * else the process-wide default `SSLSocketFactory`/`HostnameVerifier` (§9.3).
   * afirma-simple sets `disableSslChecks = !preference secureConnections` (default `secureConnections=true` ⇒ checks ON) and `secureDomainsList` from preference `secureDomainsList` (cleared if blank).
6. Caching disabled; method set.
7. **Headers** requested by the code: `Authorization: Basic <auth>` (if creds and caller didn't set `Authorization`), `Accept: */*` (if absent), `Connection: keep-alive` (if absent), `Host: <host>` (if absent), `Origin: <protocol>://<host>` (if absent). Then all caller headers are **added** (`addRequestProperty`). **What actually goes on the wire** (JDK `HttpURLConnection` silently drops "restricted" headers because `sun.net.http.allowRestrictedHeaders` is never set): `Host`, `Origin`, `Connection` (unless `close`), `Content-Length` set by the code are **ignored** — the JDK sends its own `Host` (with `:port` when non-default), `Connection: keep-alive`, computed `Content-Length`, **no `Origin`**, `User-Agent: Java/<java.version>`, and `Accept: */*`. For byte-level parity, emulate the wire behaviour, not the code's intent.
8. **Timeouts**: read timeout = instance `readTimeout` if ≠ -1 (0 = infinite); connect timeout = the `timeout` argument if ≠ -1. `-1` ⇒ Java default = **infinite** (unless `sun.net.client.defaultConnectTimeout/defaultReadTimeout` are set). Most callers pass -1 ⇒ no timeouts.
9. Connect; status code: if the decimal string starts with `4` or `5` → `HttpError(code, reasonPhrase, errorBody, url)`. Otherwise read the whole body (any 1xx/2xx/3xx; redirects are followed automatically by Java for the same protocol only — no http→https redirect following).
10. Any `IOException` (including `HttpError`, `SSLHandshakeException`, `SocketTimeoutException`): if an `HttpErrorProcessor` was given → return `processor.processHttpError(e, this, url /*rebuilt url*/, connectTimeout, method, requestHeaders)`; else rethrow.
11. **Cookies**: a static initialiser installs a process-wide `CookieManager` with `ACCEPT_ALL` (in-memory jar shared by every connection, never persisted). Triphase/intermediate servers relying on `JSESSIONID` session cookies across presign/postsign depend on this — **must be replicated** (shared in-memory cookie store for all HTTP calls of the process).

### 9.3 Process-wide trust configuration (`SslSecurityManager`, `TrustStoreManager`, `MultiX509TrustManager`)

* `configureAfirmaTrustManagers()`: if `<home>/.afirma/TrustedCertsKeystore.jks` exists and has ≥1 entry (JKS, password `changeit`), set the **default** TLS context to a trust manager that accepts a chain if **either** the JVM default trust store (cacerts) **or** the AutoFirma store trusts it (`MultiX509TrustManager`: tries each in order, throws the last error if none succeeds; `getAcceptedIssuers` = union). Default hostname verifier = JVM default. Returns false (and changes nothing) if the file is missing or empty. Called at startup by `SSLContextConfigurationTask` only when preference `secureConnections=true` **and** admin preference `allowPersonalTruststore=true`; afterwards it makes a dummy connection to `https://test.conexion.gob.es/` (100 ms timeout) to "warm up" the context.
* If `allowPersonalTruststore && allowAutoImportTrustedCerts` (both default `true`) is false → System property `blockAutoImportTrustedCerts=true`.
* `disableSslChecks()` (global): trust-all + accept-all hostnames, with a client `KeyManager` from `javax.net.ssl.keyStore`/`keyStorePassword`/`keyStoreType` (default JKS) if set. `enableSslChecks()`: restore AutoFirma trust (if previously configured) or JVM defaults.
* `TrustStoreManager` (singleton): loads the JKS at construction; if corrupt → confirm dialog `AutofirmaTrustStore.0/1`; on YES the file is deleted. `importCerts(certs…)`: creates the store if absent, skips certs already present (`X509Certificate.equals` = DER equality), alias = `subject.toString()` or `subject + " (i)"` for i = 1,2,… if taken; then stores the file. `deleteCert`, `getCertificates`, `containsCert`. Rust: the file format must remain JKS (Java KeyStore, trusted-cert entries) if interop with an existing Java installation's store is wanted; otherwise define an equivalent store at the same path — decide at project level.

### 9.4 `SSLErrorProcessor` (interactive "trust this server?")

Constructed with `headless` = `params.headless || params.sslOmitImportationDialog` (Boolean.parseBoolean). On `processHttpError(cause, …)`:

1. If `cause` is not `SSLHandshakeException` → rethrow `cause`.
2. Lazy init: if not headless, become headless when no GUI is available; read `blockAutoImportTrustedCerts` system property.
3. If blocked → rethrow. If headless → rethrow. If another confirmation dialog is currently shown (static flag) → rethrow.
4. Fetch the server chain with a trust-all connection (`downloadFromRemoteServer`). Check the **leaf** is issued for the URL host: if it has SubjectAltNames, compare against each `dNSName` (type 2) and `iPAddress` (type 7) lower-cased; if it has none, compare against the subject CN. Match rules: exact equality; wildcard only for DNS (not when the host is an IP), name must start with `*.`, not end with `.`, host must end with the name minus `*`, and the remaining host prefix must be non-empty and contain no `.` (single-label wildcard). IP detection: dotted quad with 4 parts 0–255 without leading zeros, or any string containing `:`. Mismatch → `InvalidDomainSSLCertificateException(cause, url)` (an `IOException`; `getHost()`), mapped by the app to error `400004`. Other errors fetching certs → `IOException(e)`.
5. Certs to import: if the chain has >1 cert, all **except the leaf** (issuers only); else the single cert.
6. If all already in the AutoFirma store → skip to retry. Else, if a previous dialog in this process was cancelled (static `previouslyCancelled`) → treat as cancelled. Otherwise show a YES/NO warning dialog `SSLRequestPermissionDialog.2` (with host) titled `SSLRequestPermissionDialog.1`. Not YES → mark cancelled (instance and static) and rethrow `cause`. YES → import certs, `configureAfirmaTrustManagers()`, then
7. **Retry once**: `urlManager.readUrl(url, timeout, method, requestHeaders)` (no processor, no sslConfig).
`isCancelled()` lets callers log "user refused to import".

### 9.5 `DataDownloader.downloadData(String ds, boolean gzipped=false, boolean ignoreSSLSecurity=false)`

Order: (1) `gzipped && Base64.isBase64(ds)` → gunzip(`Base64.decode(ds.replace("_","/").replace("-","+"))`); (2) `ds.trim()` starts with `http://`/`https://` → GET via installed manager with an `SSLErrorProcessor` (and a trust-all `SSLConfig` if `ignoreSSLSecurity`); (3) `ftp://` → Java URL stream; (4) `file:/` → `AOUtil.loadFile`; (5) `Base64.isBase64` → decode after `_`→`/`, `-`→`+` (decode failure → falls through); (6) return `dataSource.getBytes()` (platform charset). `null` → `IllegalArgumentException("La fuente de datos no puede ser nula")`.

### 9.6 Out-of-core: `afirma-simple` `HttpManager`

`readUrl(url, method)` always passes a fresh `SSLErrorProcessor()` (not headless). `ProxyUtil`: preference `proxyType` ∈ {`SYSTEM`,`CUSTOM`,`NONE`} (legacy: `proxySelected` + host/port); custom proxy password stored ciphered (AES key `3zevqLjBQTqWKCDEev3kNyjRWQpeuKe3xYlcdGmBYZE=`, IV `NKAe+g8shVCYWEEhLNPU0A==`, fallback DES key `8W{t2r,B`) — detailed in the preferences/UI spec.

---

## 10. Exceptions and error codes

### 10.1 `ErrorCode`

* Value object `{ code: String (exactly 6 ASCII digits, validated → IllegalArgumentException("Los codigos de error deben ser un numero de 6 digitos")), description: String|null (mutable) }`.
* `equals`/`hashCode` use **only `code`** — so codes duplicated across holder classes (see table, marked DUPLICATE) are indistinguishable at runtime (matters for the legacy SAF mapping, §10.5).
* `toString()` = `code + ": " + description`.
* `checkType(prefix)` = `code.startsWith(prefix)`; categories by first digit: `1` hardware, `2` internal, `3` third-party, `4` communication, `5` functional, `6` request (`62` = request from browser).
* Holder classes (nested static classes per category): core `ErrorCode.{Internal, ThirdParty, Communication, Functional, Request}`, plus module holders `KeyStoreErrorCode`, `BinaryErrorCode`, `XMLErrorCode`, `XAdESErrorCode`, `PdfErrorCode`, `ODFErrorCode`, `OOXMLErrorCode`, `BatchErrorCode`, `MassiveErrorCode`, `ValidationErrorCode`, `TriphaseErrorCode`, `TriServiceErrorCode`, `BatchServiceErrorCode`, `SimpleErrorCode`, `ConfiguratorErrorCode`, `PluginManagerError`. The complete list is in §10.6 so all modules share one numbering space.

### 10.2 Exception hierarchy (core)

```
java.lang.Exception
 └─ AOException (checked) implements AOControlledException { ErrorCode errorCode }
     ├─ AOFormatFileException(msg, code)                       – data not valid for the format (code chosen by thrower, e.g. 501002/510002…)
     ├─ AOInvalidSignatureFormatException(msg[, cause])          – default code 501006 COMPATIBLE_SIGNATURE_NOT_FOUND (or explicit code)
     ├─ AOUnsupportedSignAlgorithmException(msg[, cause])        – fixed code 600107 UNSUPPORTED_SIGNATURE_ALGORITHM
     ├─ AOUnsupportedSignFormatException(msg[, cause])           – fixed code 600105 UNSUPPORTED_SIGNATURE_FORMAT
     ├─ AOTriphaseException (private ctor; parsePresignException/parsePostsignException) – codes 300409..300452, + serverExceptionClassname
     ├─ ParameterException(msg[, cause], code)                   – protocol URL parsing
     │   └─ ParameterLocalAccessRequestedException               – protocol: local URL requested
     ├─ keystores.AOCancelledSMOperationException(msg)           – code 500001 CANCELLED_OPERATION (smart-card dialog cancelled)
     ├─ keystores.AuthenticationException(msg|cause)             – default code 200108 SIGNING_KEY_AUTHENTICATION_ERROR
     │   ├─ keystores.LockedKeyStoreException(…, code)           – e.g. 511003 KEYSTORE_LOCKED / 511004 SMARTCARD_LOCKED
     │   └─ keystores.PinException(…, code)                      – e.g. 501003 INVALID_SMARTCARD_PIN
     └─ RuntimeConfigNeededException { RequestType requestType (CONFIRM|PASSWORD, non-null), requestorText, param, boolean denied }
         ├─ SigningLTSException(msg[, cause, possible])          – CONFIRM, param allowSignLTSignature, text signingLts / signingLtsPossible, code 501007
         ├─ CustomRuntimeConfigNeededException (abstract) + prepareOperationWithConfirmation(Properties)
         │   └─ SignaturePolicyIncompatibilityException(msg[, op][, cause]) – CONFIRM, param avoidAGEPolicyIncompatibilities, code 501008;
         │        on confirmation removes policyIdentifier, policyIdentifierHash, policyIdentifierHashAlgorithm, policyDescription, policyQualifier
         └─ RuntimePasswordNeededException (abstract) – PASSWORD + configure(Properties, char[])
java.lang.RuntimeException
 └─ AORuntimeException implements AOControlledException { ErrorCode }
     ├─ AOCancelledOperationException([msg[, cause]])            – code 500001 CANCELLED_OPERATION
     ├─ InvalidLibraryException(msg[, cause][, code])            – default 200002 LIBRARY_NOT_FOUND
     ├─ MissingLibraryException(desc, cause, code)
     └─ InvalidOSException(expectedOS)                           – 500003 INCOMPATIBLE_OPERATING_SYSTEM, msg "Se esperaba el sistema operativo: <os>"
java.io.IOException
 ├─ InvalidDomainSSLCertificateException(cause, url) { getHost() }  – no ErrorCode field (app maps it to 400004)
 └─ http.HttpError(code, reason, body, url)
validation: signvalidation.InvalidSignatureException(msg|cause) extends AOException – code 500002 INVALID_SIGNATURE
```

Construction rules: `AOException(ErrorCode)` → message = `code.getDescription()`; `(msg, code)`; `(cause, code)` → message = description; `(msg, cause, code)`. `toString()` = Java default (`<class>: <msg>`) + `" (" + code + ")"` when a code is present, i.e. `…: msg (500001: Operacion cancelada por el usuario)`.

`AOTriphaseException.parsePresignException(String serverCode, msg, exceptionClassname)`: `"ERR-1"`…`"ERR-20"` → 300409…300428 respectively (`ERR-n` → `300408 + n`), anything else → 300451. `parsePresignException(int n, msg, Throwable cause)` = `("ERR-" + n, msg, cause.getClass().getName())`. `parsePostsignException`: `ERR-1`…`ERR-20` → 300430…300449 (`300429 + n`), else 300452.

### 10.3 `RuntimeConfigNeededException` protocol (user-intervention loop)

Signers/validators throw it when continuing needs confirmation or a password. Callers (protocol launchers, desktop sign task) implement the loop of §3.5 item 4. Messages for `requestorText` are looked up in the app's message bundle (`SimpleAfirmaMessages`), e.g. `signingLts`, `signingLtsPossible`, `agePolicyIncompatibilitySign/Cosign/CounterSign`, PDF ones like `pdfFormModified…` (format specs). If the triphase server returns such an exception serialised, the client rebuilds it and marks `setDenied(true)` (no prompt; fail).

### 10.4 Exception → error code mapping (who maps what)

| Situation / exception | ErrorCode |
|---|---|
| Any `AOControlledException` | its own `getErrorCode()` (may be `null` → treated as unknown) |
| `AOCancelledOperationException`, `AOCancelledSMOperationException` | 500001 |
| `AOInvalidSignatureFormatException` (default) | 501006 |
| `AOUnsupportedSignAlgorithmException` | 600107 |
| `AOUnsupportedSignFormatException` / unknown format name in factory (protocol) | 600105 |
| `InvalidSignatureException` (validation) | 500002 |
| `SignaturePolicyIncompatibilityException` | 501008 |
| `SigningLTSException` | 501007 |
| `InvalidLibraryException` default | 200002 |
| `InvalidOSException` | 500003 |
| `AuthenticationException` default | 200108 |
| PKCS#1: unknown algorithm / bad key / sign error / wrong cert / verify error | 600107 / 200110 / 200111 / 200112 / 200113 (§3.2) |
| JMulticard locked card / bad PIN | 511004 / 501003 |
| Triphase presign: HttpError / timeout / IO / bad response / no presigns | 300400 / 401302 / 401300 / 300401 / 300402 |
| Triphase postsign: HttpError / timeout / IO / not "OK" / bad NEWID | 300404 / 401402 / 401400 / 300405 / 300407 |
| Triphase server `ERR-n` | §10.2 |
| Cert encoding failure (triphase) | 200114 |
| `InvalidDomainSSLCertificateException` (in app) | 400004 (`Error.400004` text with `%0` = host) |
| Protocol sign: `IllegalArgumentException` | `SimpleErrorCode.Request.INVALID_FORMAT_SIGNATURE_PARAM` |
| Protocol sign: `UnsupportedOperationException` | `SimpleErrorCode.Request.UNSUPPORTED_OPERATION` |
| Protocol sign: other `Exception` | 200115 UNKNOWN_SIGNING_ERROR |
| Protocol: data loading failure | 200003 LOADING_DATA_ERROR |
| Protocol: AUTO format not identified | 501009 `SimpleErrorCode.Functional.CANT_IDENTIFY_SIGNATURE_FORMAT` |
| Validation PDF without signatures | `SignValidity(KO, NO_SIGN, 507001)` |
| Certified-PDF revision violation (validation) | `PdfErrorCode.Internal.SIGNING_PDF_WITH_CERTIFIED_SIGN` |
| Language pack import failure | `230001` (no description) |

### 10.5 How codes surface to users and to the web protocol (afirma-simple `ProtocolInvocationLauncherErrorManager`)

* **Protocol ≥ 4.1** (`ProtocolVersion.hasSupportTo(4.1)`): response text = `prefix + "AF" + code + " - " + description`, where `prefix = "err-11:="` for 500001 (cancel) and `"err-00:="` otherwise. Example: `err-00:=AF600105 - El formato de firma indicado en la operacion de firma no esta soportado`.
* **Protocol < 4.1**: legacy text `SAF_xx: <message>` via the association table below (unmapped → `SAF_53: Error desconocido`); cancellation (500001) → literally `CANCEL`.
* **Dialogs** shown to the user: title = `ProtocolLauncher.67` ("Error") for ≥ 4.1, else `ProtocolLauncher.29` = `Error %0` with `%0` = `"AF" + code`; body = `ProtocolMessages["Error.<code>"]`, falling back to the category key `Error.1XXXXX`…`Error.6XXXXX` / `Error.62XXXX`, then `Error`, then the ErrorCode description; `%0..%n` replaced with params. **GOTCHA**: a missing `else` makes hardware/internal (1xxxxx/2xxxxx) codes fall through to the final `else` branch, so they use key `Error.<code>` with fallback `Error` (generic) instead of `Error.1XXXXX`/`Error.2XXXXX`.
* Headless: logged as `AF<code>: <message>`.

Legacy SAF association (`OLD_ERRORS_ASSOCIATION`; Hashtable, last put wins):

| SAF | es_ES message (`ProtocolLauncher.N`) | ErrorCodes mapped to it (holder constant `code`) |
|---|---|---|
| `CANCEL` | `CANCEL` | ErrorCode.Functional.CANCELLED_OPERATION `500001` |
| `SAF_00` | No se han podido leer los datos a firmar | ErrorCode.Internal.LOADING_DATA_ERROR `200003` |
| `SAF_01` | La URL recibida es nula | SimpleErrorCode.Request.REQUEST_URI_NOT_FOUND `620012` |
| `SAF_02` | Protocolo no soportado | SimpleErrorCode.Request.UNSUPPORTED_REQUEST_SCHEME `620009` |
| `SAF_03` | Error en los parámetros de entrada | SimpleErrorCode.Request.PORTS_NOT_FOUND `620013`, SimpleErrorCode.Request.INVALID_FORMAT_SIGN_BATCH_PARAM `600420`, SimpleErrorCode.Request.INVALID_FORMAT_SIGNATURE_PARAM `600121`, ErrorCode.Request.DATA_NOT_FOUND `600100`, ErrorCode.Request.DATA_TO_SAVE_NOT_FOUND `600300`, ErrorCode.Request.FILE_EXTENSION_TO_SAVE_NOT_FOUND `600307`, ErrorCode.Request.FILENAME_TO_SAVE_NOT_FOUND `600306`, ErrorCode.Request.ID_SESSION_TO_SIGN_BATCH_NOT_FOUND `600403`, ErrorCode.Request.INVALID_COUNTERSIGNATURE_INDEX `600112`, ErrorCode.Request.INVALID_PARAMS_TO_PRESIGN `600701`, ErrorCode.Request.INVALID_PARAMS_TO_POSTSIGN `600702`, ErrorCode.Request.INVALID_PRESIGN_BATCH_URL `600413`, ErrorCode.Request.INVALID_POSTSIGN_BATCH_URL `600415`, ErrorCode.Request.INVALID_RETRIEVE_URL_TO_SIGN `600116`, ErrorCode.Request.INVALID_SESSION_ID_TO_SAVE `600303`, ErrorCode.Request.INVALID_SESSION_ID_TO_SELECT_CERT `600201`, ErrorCode.Request.INVALID_SESSION_ID_TO_SIGN `600120`, ErrorCode.Request.INVALID_SESSION_ID_TO_SIGN_BATCH `600410`, ErrorCode.Request.INVALID_STORAGE_URL_TO_SAVE `600304`, ErrorCode.Request.INVALID_STORAGE_URL_TO_SELECT_CERT `600202`, ErrorCode.Request.INVALID_STORAGE_URL_TO_SIGN `600118`, ErrorCode.Request.INVALID_STORAGE_URL_TO_SIGN_BATCH `600411`, ErrorCode.Request.INVALID_TIMESTAMP_HASH_ALGORITHM `600113`, ErrorCode.Request.PRESIGN_BATCH_URL_NOT_FOUND `600405`, ErrorCode.Request.POSTSIGN_BATCH_URL_NOT_FOUND `600406`, ErrorCode.Request.RETRIEVE_URL_TO_SAVE_NOT_FOUND `600301`, ErrorCode.Request.RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL `600117`, ErrorCode.Request.RETRIEVE_URL_TO_SIGN_NOT_FOUND `600101`, ErrorCode.Request.SIGNATURE_ALGORITHM_NOT_FOUND `600106`, ErrorCode.Request.SIGNATURE_FORMAT_NOT_FOUND `600104`, ErrorCode.Request.STORAGE_URL_TO_SAVE_NOT_FOUND `600302`, ErrorCode.Request.STORAGE_URL_TO_SELECT_CERT_NOT_FOUND `600200`, ErrorCode.Request.STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND `600402`, ErrorCode.Request.STORAGE_URL_TO_SIGN_NOT_FOUND `600102`, ErrorCode.Request.UNSUPPORTED_CIPHER_KEY `600009`, ErrorCode.Request.UNSUPPORTED_COUNTERSIGN_CONFIG `600110`, ErrorCode.Request.UNSUPPORTED_POLICY_HASH_ALGORITHM `600111`, ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM `600107`, SimpleErrorCode.Request.MALFORMED_REQUEST_TO_SOCKET `620016`, BatchErrorCode.Request.INVALID_PARAMS_TO_PRESIGN_JSON_BATCH `600417`, BatchErrorCode.Request.INVALID_PARAMS_TO_PRESIGN_XML_BATCH `600501`, ErrorCode.Internal.UNKNOWN_SIGNING_ERROR `200115`, SimpleErrorCode.Internal.UNKNOWN_SELECTING_CERT_ERROR `200201`, SimpleErrorCode.Internal.UNKNOWN_BATCH_ERROR `200413`, SimpleErrorCode.Internal.UNKNOWN_LOADING_DATA_ERROR `200600`, SimpleErrorCode.Internal.UNKNOWN_SAVING_DATA_ERROR `200305`, SimpleErrorCode.Communication.READING_FROM_SOCKET `420502`. Note: `UNKNOWN_SIGNING_ERROR 200115` is put first with SAF_09 and then again with SAF_03 (last wins). |
| `SAF_04` | Operación no soportada. Compruebe que dispone de la última versión de Autofirma. | SimpleErrorCode.Request.UNSUPPORTED_OPERATION `600002` |
| `SAF_05` | No se ha podido guardar los datos | SimpleErrorCode.Internal.CANT_SAVE_FILE `200301` |
| `SAF_06` | Formato de firma no soportado | ErrorCode.Request.UNSUPPORTED_SIGNATURE_FORMAT `600105` |
| `SAF_08` | Error accediendo al almacén de claves y certificados | KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR `201101` |
| `SAF_09` | Error realizando la firma electrónica | ErrorCode.Internal.SIGNING_PKCS1_ERROR `200111`, SimpleErrorCode.Internal.UNKNOWN_SIGNING_BY_SOCKETS_ERROR `200118` (and therefore core `ErrorCode.Internal.UNSUPPORTED_HASH_ALGORITHM` 200118, same code) |
| `SAF_11` | Error en el envio del resultado de la operación. | SimpleErrorCode.Communication.SENDING_RESULT_OPERATION `401200`, SimpleErrorCode.Communication.SENDING_RESULT_OPERATION_BY_SOCKET `420501` |
| `SAF_12` | Error en el cifrado de los datos a enviar | SimpleErrorCode.Internal.ENCRIPTING_SIGNATURE `200100`, SimpleErrorCode.Internal.ENCRIPTING_SIGNING_CERT `200101`, SimpleErrorCode.Internal.ENCRIPTING_SIGNATURE_EXTRA_DATA `200116`, SimpleErrorCode.Internal.ENCRIPTING_SELECTED_CERT `200200`, SimpleErrorCode.Internal.ENCRIPTING_BATCH_RESULT `200400`, SimpleErrorCode.Internal.ENCRIPTING_BATCH_SIGNING_CERT `200401`, SimpleErrorCode.Internal.ENCRYPTING_PARAMS_ERROR `220004` |
| `SAF_13` | Se ha pedido acceso a una dirección local, pero por seguridad se ha bloqueado el acceso | ErrorCode.Request.LOCAL_RETRIEVE_URL `600010`, ErrorCode.Request.LOCAL_PRESIGN_BATCH_URL `600414`, ErrorCode.Request.LOCAL_POSTSIGN_BATCH_URL `600416`, ErrorCode.Request.LOCAL_STORAGE_URL_TO_SAVE `600305`, ErrorCode.Request.LOCAL_STORAGE_URL_TO_SELECT_CERT `600203`, ErrorCode.Request.LOCAL_STORAGE_URL_TO_SIGN `600119`, ErrorCode.Request.LOCAL_STORAGE_URL_TO_SIGN_BATCH `600412` |
| `SAF_14` | (HTML) La aplicación está obsoleta… | SimpleErrorCode.Internal.NEEDS_UPDATED_VERSION `200701` |
| `SAF_15` | Error en el descifrado de los datos | SimpleErrorCode.Internal.DECRYPTING_PARAMS_ERROR `220002` |
| `SAF_16` | Error al recuperar los datos del servidor intermedio | SimpleErrorCode.Internal.ERROR_RECIVED_FROM_CLIENT `220003`, SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_OPERATION `401100`, SimpleErrorCode.Communication.RECIVING_DATA_OF_CERT_OPERATION `401101`, SimpleErrorCode.Communication.RECIVING_DATA_OF_BATCH_OPERATION `401102`, SimpleErrorCode.Communication.RECIVING_DATA_OF_LOAD_OPERATION `401104`, SimpleErrorCode.Communication.RECIVING_DATA_OF_SAVE_OPERATION `401103`, SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION `401105` |
| `SAF_17` | Los datos proporcionados no son una firma electrónica reconocida | SimpleErrorCode.Functional.CANT_IDENTIFY_SIGNATURE_FORMAT `501009` |
| `SAF_18` | Error al descodificar el certificado de firma | ErrorCode.Internal.ENCODING_SIGNING_CERTIFICATE `200114` |
| `SAF_19` | No hay ningun certificado válido en su almacén… | SimpleErrorCode.Functional.NO_CERTS_FOUND_SIGNING `501001`, SimpleErrorCode.Functional.NO_CERTS_FOUND_SELECTING_CERT `502001`, SimpleErrorCode.Functional.NO_CERTS_FOUND_SIGNING_BATCH `504001` (and therefore core `ErrorCode.Functional.CERTIFICATE_NEEDED` 501001, same code) |
| `SAF_20` | Error en el procesado del lote de firma. | SimpleErrorCode.Internal.INTERNAL_LOCAL_BATCH_ERROR `200412` |
| `SAF_21` | La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible. | SimpleErrorCode.Request.UNSUPPORTED_PROTOCOL_VERSION `620011` |
| `SAF_23` | Se ha establecido una política de firma no válida o parámetros no compatibles con ella. | ErrorCode.Functional.SIGNING_WITH_POLICY_INCOMPATIBILITY `501008` |
| `SAF_25` | Error en la lectura de los datos a cargar. | SimpleErrorCode.Internal.CANT_LOAD_FILE `200601` |
| `SAF_26` | Error en la comunicación con el servicio de firma de lotes. | BatchErrorCode.Communication.JSON_BATCH_PRESIGN_COMMUNICATION_ERROR `401501`, BatchErrorCode.Communication.XML_BATCH_PRESIGN_COMMUNICATION_ERROR `401701` |
| `SAF_27` | El servicio informó de un error durante la firma del lote. | SimpleErrorCode.Internal.INTERNAL_JSON_BATCH_ERROR `200410`, SimpleErrorCode.Internal.INTERNAL_XML_BATCH_ERROR `200411`, BatchErrorCode.ThirdParty.XML_BATCH_PRESIGN_ERROR `300701`, BatchErrorCode.ThirdParty.XML_BATCH_POSTSIGN_ERROR `300702` |
| `SAF_28` | El fichero no es un PDF o es un PDF no soportado. | PdfErrorCode.Functional.PDF_DOCUMENT_NEEDED `510005` |
| `SAF_29` | Las firmas XAdES Enveloped solo pueden realizarse sobre datos XML. | XMLErrorCode.Functional.XML_DOCUMENT_NEEDED `510002` |
| `SAF_30` | El formato de los datos a firmar no es adecuado para el tipo de firma seleccionado. | ErrorCode.Functional.INVALID_FORMAT_FILE `501002` |
| `SAF_31` | Los datos introducidos no se corresponden con un objeto de firma. | ErrorCode.Functional.COMPATIBLE_SIGNATURE_NOT_FOUND `501006` |
| `SAF_32` | La factura ya tiene una firma electrónica y no admite firmas adicionales. | XAdESErrorCode.Functional.FACTURAE_ALREADY_SIGNED `510008` |
| `SAF_33` | La contraseña proporcionada no es válida para el PDF actual o no se proporcionó ninguna contraseña. | PdfErrorCode.Internal.SIGNING_PDF_WITH_BAD_PASSWORD `212004`, PdfErrorCode.Internal.SIGNING_PDF_WITHOUT_PASSWORD `212005` |
| `SAF_34` | El PDF contiene firmas no registradas. | PdfErrorCode.Internal.SIGNING_PDF_WITH_UNREGISTER_SIGNATURES `212003` |
| `SAF_35` | El PDF está certificado. | PdfErrorCode.Internal.SIGNING_PDF_WITH_CERTIFIED_SIGN `212007` |
| `SAF_38` | El archivo que intenta firmar no es una factura electrónica reconocida. | XAdESErrorCode.Functional.FACTURAE_NEEDED `510009` |
| `SAF_39` | La firma de entrada no es válida. | ErrorCode.Functional.INVALID_SIGNATURE `500002` |
| `SAF_41` | El uso de este trámite web requiere una versión más reciente de Autofirma.\nActualice a la última versión disponible. | SimpleErrorCode.Functional.MINIMUM_VERSION_NON_SATISTIED `500005` |
| `SAF_43` | Error durante la firma visible del PDF. | SimpleErrorCode.Functional.VISIBLE_SIGNATURE_IS_MANDATORY `501010` |
| `SAF_44` | La firma no contiene los datos y no se compatible con la configuración seleccionada | BinaryErrorCode.Functional.SIGNATURE_DOESNT_CONTAIN_DATA `510001` |
| `SAF_45` | No se pudo abrir un socket para la comunicación con la aplicación | SimpleErrorCode.Internal.SOCKET_INITIALIZING_ERROR `220001` |
| `SAF_46` | Id de sesión inválido | SimpleErrorCode.Request.INVALID_SESSION_ID `620010` |
| `SAF_48` | (key `ProtocolLauncher.63`, absent from every bundle) | — (declared, no mapping) |
| `SAF_49` | (key `ProtocolLauncher.64`, absent from every bundle) | — (declared, no mapping) |
| `SAF_51` | El tipo de clave del certificado no está soportado. | ErrorCode.Internal.INVALID_SIGNING_KEY `200110` |
| `SAF_52` | El almacen de claves esta bloqueado | ErrorCode.Functional.KEYSTORE_LOCKED `511003`, ErrorCode.Functional.SMARTCARD_LOCKED `511004` |
| `SAF_53` | Error desconocido | (fallback for any unmapped code) |

(Exact `SimpleErrorCode`/`BatchErrorCode`/… numeric values are in §10.6. The full protocol response format belongs to the protocol spec.)

### 10.6 Complete error-code table (all modules)

Generated from every `new ErrorCode("NNNNNN", "…")` in non-test sources (322 definitions). Descriptions are the exact Java strings (ASCII, no accents, leading spaces preserved). Rows marked **DUPLICATE CODE** share a numeric code with another definition; because `ErrorCode.equals` compares only the code, they are the same error at runtime.

| Code | Holder class . group | Constant | Description (exact Java string) | Module |
|---|---|---|---|---|
| `102025` | KeyStoreErrorCode.Hardware | `SMARTCARD_LOCKED` | La tarjeta inteligente esta bloqueada | afirma-core-keystores |
| `200002` | ErrorCode.Internal | `LIBRARY_NOT_FOUND` | No se encuentran dependencias necesarias para la ejecucion de la operacion | afirma-core |
| `200003` | ErrorCode.Internal | `LOADING_DATA_ERROR` | Error durante la carga de datos | afirma-core |
| `200004` | SimpleErrorCode.Internal | `CANT_LOAD_HELP` | No se ha podido cargar correctamente la ayuda | afirma-simple |
| `200005` | SimpleErrorCode.Internal | `NOT_VALID_PLUGIN` | Plugin no valido | afirma-simple |
| `200006` | ErrorCode.Internal | `ERROR_IMPORT_LANGUAGE` | Error al importar idioma | afirma-core |
| `200100` | SimpleErrorCode.Internal | `ENCRIPTING_SIGNATURE` | Error al cifrar la firma para enviarla al servidor intermedio | afirma-simple |
| `200101` | SimpleErrorCode.Internal | `ENCRIPTING_SIGNING_CERT` | Error al cifrar el certificado de firma para enviarlo al servidor intermedio | afirma-simple |
| `200102` | ErrorCode.Internal | `LOADING_LOCAL_FILE_ERROR` | Error al cargar el fichero local para realizar la firma | afirma-core |
| `200108` | ErrorCode.Internal | `SIGNING_KEY_AUTHENTICATION_ERROR` | No se pudo acceder a la clave de firma | afirma-core |
| `200110` | ErrorCode.Internal | `INVALID_SIGNING_KEY` | La clave de firma no es valida o no es compatible con el algoritmo seleccionado | afirma-core |
| `200111` | ErrorCode.Internal | `SIGNING_PKCS1_ERROR` | Error al generar la firma PKCS#1 | afirma-core |
| `200112` | ErrorCode.Internal | `INVALID_PKCS1_VALUE` | La firma no se ha generado con el certificado seleccionado | afirma-core |
| `200113` | ErrorCode.Internal | `VERIFING_PKCS1_ERROR` | No se pudo verificar la firma generada | afirma-core |
| `200114` | ErrorCode.Internal | `ENCODING_SIGNING_CERTIFICATE` | Error codificando el certificado de firma | afirma-core |
| `200115` | ErrorCode.Internal | `UNKNOWN_SIGNING_ERROR` | Error desconocido durante la operacion de firma | afirma-core |
| `200116` | SimpleErrorCode.Internal | `ENCRIPTING_SIGNATURE_EXTRA_DATA` | Error al cifrar la informacion extra de firma para enviarla al servidor intermedio | afirma-simple |
| `200117` | SimpleErrorCode.Internal | `POSTPROCESING_SIGNATURE` | Error en el postproceso de la firma | afirma-simple |
| `200118` **(DUPLICATE CODE)** | ErrorCode.Internal | `UNSUPPORTED_HASH_ALGORITHM` | No se soporta un algoritmo de hash establecido internamente | afirma-core |
| `200118` **(DUPLICATE CODE)** | SimpleErrorCode.Internal | `UNKNOWN_SIGNING_BY_SOCKETS_ERROR` | Error desconocido durante la operacion de firma usando la comunicacion por sockets | afirma-simple |
| `200119` | SimpleErrorCode.Internal | `LOAD_FILE_TO_VIEW` | Error al cargar el fichero local para visualizar la firma | afirma-simple |
| `200200` | SimpleErrorCode.Internal | `ENCRIPTING_SELECTED_CERT` | Error al cifrar el certificado seleccionado para enviarlo al servidor intermedio | afirma-simple |
| `200201` | SimpleErrorCode.Internal | `UNKNOWN_SELECTING_CERT_ERROR` | Error desconocido durante la operacion de seleccion de certificado | afirma-simple |
| `200301` | SimpleErrorCode.Internal | `CANT_SAVE_FILE` | No se ha podido guardar el fichero en disco | afirma-simple |
| `200305` | SimpleErrorCode.Internal | `UNKNOWN_SAVING_DATA_ERROR` | Error general durante la operacion de guardado de datos | afirma-simple |
| `200400` | SimpleErrorCode.Internal | `ENCRIPTING_BATCH_RESULT` | Error al cifrar la informacion de las firmas del lote para enviarla al servidor intermedio | afirma-simple |
| `200401` | SimpleErrorCode.Internal | `ENCRIPTING_BATCH_SIGNING_CERT` | Error al cifrar el certificado de firma para enviarlo al servidor intermedio | afirma-simple |
| `200410` **(DUPLICATE CODE)** | BatchServiceErrorCode.Internal | `INTERNAL_JSON_BATCH_ERROR` | Error interno al procesar un lote de firmas JSON | afirma-server-triphase-signer |
| `200410` **(DUPLICATE CODE)** | SimpleErrorCode.Internal | `INTERNAL_JSON_BATCH_ERROR` | Error interno al procesar un lote de firmas JSON | afirma-simple |
| `200411` | SimpleErrorCode.Internal | `INTERNAL_XML_BATCH_ERROR` | Error interno al procesar un lote de firmas XML | afirma-simple |
| `200412` | SimpleErrorCode.Internal | `INTERNAL_LOCAL_BATCH_ERROR` | Error interno realizando la firma batch local | afirma-simple |
| `200413` | SimpleErrorCode.Internal | `UNKNOWN_BATCH_ERROR` | Error desconocido al procesar un lote de firmas | afirma-simple |
| `200600` | SimpleErrorCode.Internal | `UNKNOWN_LOADING_DATA_ERROR` | Error general durante la operacion de carga de fichero | afirma-simple |
| `200601` | SimpleErrorCode.Internal | `CANT_LOAD_FILE` | Error al cargar el fichero local | afirma-simple |
| `200701` | SimpleErrorCode.Internal | `NEEDS_UPDATED_VERSION` | Se necesita actualizar la aplicacion | afirma-simple |
| `200702` | SimpleErrorCode.Internal | `NO_DETECTED_PROXIES` | No se han detectado proxies en el sisema | afirma-simple |
| `200800` | SimpleErrorCode.Internal | `ERROR_LOAD_TRUSTED_CERT` | Error al cargar el certificado de confianza | afirma-simple |
| `200801` | SimpleErrorCode.Internal | `TRUSTSTORE_INCORRECT_INSTALLATION` | El almacen de confianza de Autofirma no se encuentra instalado correctamente | afirma-simple |
| `201101` | KeyStoreErrorCode.Internal | `LOADING_KEYSTORE_INTERNAL_ERROR` | Error generico al cargar el almacen de certificados | afirma-core-keystores |
| `201103` | KeyStoreErrorCode.Internal | `LOADING_PRIVATE_KEY_ERROR` | Error al cargar la clave del certificado | afirma-core-keystores |
| `201106` | KeyStoreErrorCode.Internal | `LOADING_CERTIFICATE_ERROR` | Error al cargar el certificado suelto o en PKCS#7 | afirma-core-keystores |
| `201107` | KeyStoreErrorCode.Internal | `LOADING_WINDOWS_KEYSTORE_ERROR` | Error al cargar el almacen de certificados de Windows | afirma-core-keystores |
| `201108` | KeyStoreErrorCode.Internal | `LOADING_MOZILLA_KEYSTORE_ERROR` | Error al cargar el almacen de certificados de Mozilla | afirma-core-keystores |
| `201109` | KeyStoreErrorCode.Internal | `LOADING_APPLE_KEYSTORE_ERROR` | Error al cargar el almacen de certificados Apple KeyRing | afirma-core-keystores |
| `201110` | KeyStoreErrorCode.Internal | `LOADING_PKCS12_KEYSTORE_ERROR` | Error al cargar el almacen de certificados PKCS#12 | afirma-core-keystores |
| `201111` | KeyStoreErrorCode.Internal | `LOADING_JAVA_KEYSTORE_ERROR` | Error al cargar el almacen de certificados JKS | afirma-core-keystores |
| `201112` | KeyStoreErrorCode.Internal | `LOADING_PUBLIC_WINDOWS_KEYSTORE_ERROR` | Error al cargar el almacen de certificados de claves publicas de Windows | afirma-core-keystores |
| `201113` | KeyStoreErrorCode.Internal | `LOADING_PKCS11_KEYSTORE_ERROR` | Error al cargar el almacen de certificados a traves del PKCS#11 | afirma-core-keystores |
| `201114` | KeyStoreErrorCode.Internal | `LOADING_JMULTICARD_KEYSTORE_ERROR` | Error al cargar el almacen de certificados con JMulticard | afirma-core-keystores |
| `201115` | KeyStoreErrorCode.Internal | `LOADING_FILE_CERTSTORE_ERROR` | Error al cargar un certificado desde fichero | afirma-core-keystores |
| `201116` | KeyStoreErrorCode.Internal | `UNDEFINED_DEFAULT_KEYSTORE` | No hay definido un almacen de claves por defecto para este sistema operativo | afirma-core-keystores |
| `211001` | BinaryErrorCode.Internal | `UNKWNON_BINARY_SIGNING_ERROR` | Error desconocido en la generacion de la firma binaria | afirma-crypto-core-pkcs7 |
| `211002` | BinaryErrorCode.Internal | `INTERNAL_BINARY_SIGNING_ERROR` | Error interno en la generacion de la firma binaria | afirma-crypto-core-pkcs7 |
| `211003` | BinaryErrorCode.Internal | `GENERATING_TIMESTAMP_ERROR` | Error generando sello de tiempo binario | afirma-crypto-core-pkcs7 |
| `212001` | PdfErrorCode.Internal | `UNKWNON_PADES_SIGNING_ERROR` | Error desconocido en la generacion de la firma PAdES | afirma-crypto-pdf-common |
| `212002` | PdfErrorCode.Internal | `INTERNAL_PADES_SIGNING_ERROR` | Error interno en la generacion de la firma PAdES | afirma-crypto-pdf-common |
| `212003` | PdfErrorCode.Internal | `SIGNING_PDF_WITH_UNREGISTER_SIGNATURES` | Se esta intentando firmar una firma PDF con firmas sin registrar | afirma-crypto-pdf-common |
| `212004` | PdfErrorCode.Internal | `SIGNING_PDF_WITH_BAD_PASSWORD` | La contrasena del PDF no era correcta | afirma-crypto-pdf-common |
| `212005` | PdfErrorCode.Internal | `SIGNING_PDF_WITHOUT_PASSWORD` | El PDF necesita contrasena | afirma-crypto-pdf-common |
| `212006` | PdfErrorCode.Internal | `SIGNING_PDF_WITH_MODIFIED_FORM` | Se esta intentando firmar un PDF con un formulario modificado despues de una firma anterior | afirma-crypto-pdf-common |
| `212007` | PdfErrorCode.Internal | `SIGNING_PDF_WITH_CERTIFIED_SIGN` | Se esta intentando firmar un PDF certificado que no admite nuevas firmas | afirma-crypto-pdf-common |
| `212008` | PdfErrorCode.Internal | `SIGNING_PDF_WITH_SUSPICION_OF_PSA` | Se esta intentando firmar un PDF sospechoso de haber sido modificado tras la firma | afirma-crypto-pdf-common |
| `213001` | XMLErrorCode.Internal | `UNKWNON_XML_SIGNING_ERROR` | Error desconocido en la generacion de la firma XML | afirma-crypto-core-xml |
| `213002` | XMLErrorCode.Internal | `INTERNAL_XML_SIGNING_ERROR` | Error interno en la generacion de la firma XML | afirma-crypto-core-xml |
| `213003` | ODFErrorCode.Internal | `UNKWNON_ODF_SIGNING_ERROR` | Error desconocido en la generacion de la firma ODF | afirma-crypto-odf |
| `213004` **(DUPLICATE CODE)** | XMLErrorCode.Internal | `UNSUPPORTED_TRANSFORMATION_ALGORITHM` | El tipo de transformacion declarado no esta soportado | afirma-crypto-core-xml |
| `213004` **(DUPLICATE CODE)** | ODFErrorCode.Internal | `INTERNAL_ODF_SIGNING_ERROR` | Error interno en la generacion de la firma ODF | afirma-crypto-odf |
| `213005` | OOXMLErrorCode.Internal | `UNKWNON_OOXML_SIGNING_ERROR` | Error desconocido en la generacion de la firma OOXML | afirma-crypto-ooxml |
| `213006` | OOXMLErrorCode.Internal | `INTERNAL_OOXML_SIGNING_ERROR` | Error interno en la generacion de la firma OOXML | afirma-crypto-ooxml |
| `214001` | ErrorCode.Internal | `BUILDING_ASIC_CONTAINER_ERROR` | Error al construir el contenedor ASiC de la nueva firma | afirma-core |
| `220001` | SimpleErrorCode.Internal | `SOCKET_INITIALIZING_ERROR` | No se pudo abrir el socket de comunicacion | afirma-simple |
| `220002` | SimpleErrorCode.Internal | `DECRYPTING_PARAMS_ERROR` | Error desencriptando los datos del servidor | afirma-simple |
| `220003` | SimpleErrorCode.Internal | `ERROR_RECIVED_FROM_CLIENT` | El servicio cliente ya notifico un error durante la peticion | afirma-simple |
| `220004` | SimpleErrorCode.Internal | `ENCRYPTING_PARAMS_ERROR` | Error encriptando los datos del servidor | afirma-simple |
| `220008` | SimpleErrorCode.Internal | `LOADING_SSL_KEYSTORE_ERROR` | No se ha podido cargar el almacen de claves SSL | afirma-simple |
| `230001` | LanguageManager (inline, no description) | `(anonymous)` | (null description; thrown when importing a language pack fails) | afirma-core |
| `230100` | SimpleErrorCode.Internal | `GENERIC_LANGUAGE_IMPORT_ERROR` | Error importando el idioma | afirma-simple |
| `230101` | SimpleErrorCode.Internal | `CANT_READ_FILE` | No se ha podido leer correctamente el archivo ZIP | afirma-simple |
| `230102` | SimpleErrorCode.Internal | `CANT_CREATE_DIRECTORY` | Se ha producido un error al crear el directorio del idioma | afirma-simple |
| `230200` | PluginManagerError.Internal | `PLUGIN_ERROR` | Error desconocido con el plugin | afirma-simple-plugins-manager |
| `230201` | PluginManagerError.Internal | `UNINSTALL_PLUGIN_ERROR` | Ocurrio un error al desinstalar el plugin | afirma-simple-plugins-manager |
| `230202` | PluginManagerError.Internal | `ERROR_IN_PLUGIN` | El propio plugin devolvio un error durante su instalacion | afirma-simple-plugins-manager |
| `230203` | PluginManagerError.Internal | `CANT_REMOVE_LOADED_PLUGIN` | Ha ocurrido un error al eliminar el plugin anterior | afirma-simple-plugins-manager |
| `230204` | PluginManagerError.Internal | `PLUGIN_DIRECTORY_ERROR` | El plugin seleccionado ya se encuentra instalado | afirma-simple-plugins-manager |
| `230205` | PluginManagerError.Internal | `PLUGIN_LOAD_ERROR` | Ha ocurrido un error al intentar cargar el plugin | afirma-simple-plugins-manager |
| `230206` | PluginManagerError.Internal | `INSTALLED_PLUGIN_NOT_FOUND` | No se encontraron los ficheros de un plugin previamente instalado | afirma-simple-plugins-manager |
| `230300` | ConfiguratorErrorCode.Internal | `IMPORTING_PREFERENCES_ERROR` | Error desconocido importando las preferencias | afirma-ui-simple-configurator-common |
| `230301` | ConfiguratorErrorCode.Internal | `CANT_READ_PREFERENCES_FILE` | No se pudo leer el fichero de preferencias | afirma-ui-simple-configurator-common |
| `230302` | ConfiguratorErrorCode.Internal | `INVALID_XML_PREFERENCES_FILE` | El fichero de preferencia no es un XML | afirma-ui-simple-configurator-common |
| `230303` | ConfiguratorErrorCode.Internal | `INVALID_FORMAT_PREFERENCES_FILE` | El fichero de preferencias no tiene un formato valido | afirma-ui-simple-configurator-common |
| `300001` | BinaryErrorCode.ThirdParty | `BOUNCYCASTLE_VERSION_NOT_SUPPORTED` | Se ha encontrado una version de Spongycastle no soportada | afirma-crypto-core-pkcs7 |
| `300002` | PdfErrorCode.ThirdParty | `ITEXT_VERSION_NOT_SUPPORTED` | Se ha encontrado una version de iText no soportada | afirma-crypto-pdf-common |
| `300003` | KeyStoreErrorCode.ThirdParty | `SUN_MSCAPI_PROVIDER_NOT_FOUND` | No se ha encontrado el proveedor MSCAPI de Sun | afirma-core-keystores |
| `300004` | KeyStoreErrorCode.ThirdParty | `AFIRMA_MSCAPI_ADDRESBOOK_PROVIDER_NOT_FOUND` | No se ha encontrado el proveedor MSCAPI del Cliente @firma | afirma-core-keystores |
| `300005` | KeyStoreErrorCode.ThirdParty | `AFIRMA_SINGLE_CERT_PROVIDER_NOT_FOUND` | No se ha encontrado el proveedor SingleCert del Cliente @firma | afirma-core-keystores |
| `300202` | ErrorCode.ThirdParty | `INVALID_OPERATION_XML` | La respuesta del servidor intermedio al descargar la informacion no es un XML valido | afirma-core |
| `300400` | ErrorCode.ThirdParty | `PRESIGN_HTTP_ERROR` | El servicio de prefirma devolvio un error HTTP | afirma-core |
| `300401` | ErrorCode.ThirdParty | `MALFORMED_PRESIGN_RESPONSE` | La respuesta del servidor trifasico al hacer la prefirma no es valida | afirma-core |
| `300402` | ErrorCode.ThirdParty | `PRESIGNS_NOT_FOUND` | No se han obtenido prefirmas del servicio de prefirma | afirma-core |
| `300404` | ErrorCode.ThirdParty | `POSTSIGN_HTTP_ERROR` | El servicio de postfirma devolvio un error HTTP | afirma-core |
| `300405` | ErrorCode.ThirdParty | `POSTSIGN_ERROR` | La respuesta del servidor trifasico al hacer la postfirma no es valida | afirma-core |
| `300407` | ErrorCode.ThirdParty | `MALFORMED_POSTSIGN_RESPONSE` | El servidor trifasico devolvio una respuesta con texto OK pero no llega el formato correcto | afirma-core |
| `300409` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_1` | ERR-1 en la prefirma: No se ha indicado la operacion a realizar | afirma-core |
| `300410` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_2` | ERR-2 en la prefirma: No se ha indicado el identificador del documento | afirma-core |
| `300411` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_3` | ERR-3 en la prefirma: No se ha indicado el algoritmo de firma | afirma-core |
| `300412` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_4` | ERR-4 en la prefirma: No se ha indicado el formato de firma | afirma-core |
| `300413` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_5` | ERR-5 en la prefirma: No se ha indicado el certificado de usuario | afirma-core |
| `300414` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_6` | ERR-6 en la prefirma: El formato de los parametros adicionales suministrados es erroneo | afirma-core |
| `300415` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_7` | ERR-7 en la prefirma: El certificado de usuario no esta en formato X.509 | afirma-core |
| `300416` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_8` | ERR-8 en la prefirma: Formato de firma no soportado | afirma-core |
| `300417` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_9` | ERR-9 en la prefirma: Error realizando la prefirma | afirma-core |
| `300418` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_10` | ERR-10 en la prefirma: Error al almacenar el documento | afirma-core |
| `300419` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_11` | ERR-11 en la prefirma: Operacion desconocida | afirma-core |
| `300420` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_12` | ERR-12 en la prefirma: Error realizando la postfirma | afirma-core |
| `300421` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_13` | ERR-13 en la prefirma: No se indicado una sub-operacion valida a realizar (firma, cofirma,...) | afirma-core |
| `300422` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_14` | ERR-14 en la prefirma: Error al recuperar el documento | afirma-core |
| `300423` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_15` | ERR-15 en la prefirma: El formato de los datos de sesion suministrados es erroneo | afirma-core |
| `300424` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_16` | ERR-16 en la prefirma: Error al generar el codigo de verificacion de las firmas | afirma-core |
| `300425` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_17` | ERR-17 en la prefirma: Error al comprobar el codigo de verificacion de las firmas | afirma-core |
| `300426` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_18` | ERR-18 en la prefirma: Error de integridad en la firma | afirma-core |
| `300427` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_19` | ERR-19 en la prefirma: El formato de los datos de operacion suministrados es erroneo | afirma-core |
| `300428` | ErrorCode.ThirdParty | `TRI_SERVER_PRESIGN_ERROR_20` | ERR-20 en la prefirma: Algoritmo de firma no soportado | afirma-core |
| `300430` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_1` | ERR-1 en la postfirma: No se ha indicado la operacion a realizar | afirma-core |
| `300431` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_2` | ERR-2 en la postfirma: No se ha indicado el identificador del documento | afirma-core |
| `300432` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_3` | ERR-3 en la postfirma: No se ha indicado el algoritmo de firma | afirma-core |
| `300433` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_4` | ERR-4 en la postfirma: No se ha indicado el formato de firma | afirma-core |
| `300434` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_5` | ERR-5 en la postfirma: No se ha indicado el certificado de usuario | afirma-core |
| `300435` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_6` | ERR-6 en la postfirma: El formato de los parametros adicionales suministrados es erroneo | afirma-core |
| `300436` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_7` | ERR-7 en la postfirma: El certificado de usuario no esta en formato X.509 | afirma-core |
| `300437` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_8` | ERR-8 en la postfirma: Formato de firma no soportado | afirma-core |
| `300438` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_9` | ERR-9 en la postfirma: Error realizando la prefirma | afirma-core |
| `300439` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_10` | ERR-10 en la postfirma: Error al almacenar el documento | afirma-core |
| `300440` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_11` | ERR-11 en la postfirma: Operacion desconocida | afirma-core |
| `300441` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_12` | ERR-12 en la postfirma: Error realizando la postfirma | afirma-core |
| `300442` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_13` | ERR-13 en la postfirma: No se indicado una sub-operacion valida a realizar (firma, cofirma,...) | afirma-core |
| `300443` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_14` | ERR-14 en la postfirma: Error al recuperar el documento | afirma-core |
| `300444` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_15` | ERR-15 en la postfirma: El formato de los datos de sesion suministrados es erroneo | afirma-core |
| `300445` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_16` | ERR-16 en la postfirma: Error al generar el codigo de verificacion de las firmas | afirma-core |
| `300446` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_17` | ERR-17 en la postfirma: Error al comprobar el codigo de verificacion de las firmas | afirma-core |
| `300447` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_18` | ERR-18 en la postfirma: Error de integridad en la firma | afirma-core |
| `300448` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_19` | ERR-19 en la postfirma: El formato de los datos de operacion suministrados es erroneo | afirma-core |
| `300449` | ErrorCode.ThirdParty | `TRI_SERVER_POSTSIGN_ERROR_20` | ERR-20 en la postfirma: Algoritmo de firma no soportado | afirma-core |
| `300451` | ErrorCode.ThirdParty | `TRI_SERVER_UNKNOWN_PRESIGN_ERROR` | No se reconoce el error remitido por el servicio de prefirma | afirma-core |
| `300452` | ErrorCode.ThirdParty | `TRI_SERVER_UNKNOWN_POSTSIGN_ERROR` | No se reconoce el error remitido por el servicio de postfirma | afirma-core |
| `300601` | BatchErrorCode.ThirdParty | `JSON_BATCH_PRESIGN_ERROR` | El servicio de prefirma de lotes JSON devolvio un error | afirma-crypto-batch-client |
| `300602` | BatchErrorCode.ThirdParty | `JSON_BATCH_POSTSIGN_ERROR` | El servicio de postfirma de lotes JSON devolvio un error | afirma-crypto-batch-client |
| `300701` | BatchErrorCode.ThirdParty | `XML_BATCH_PRESIGN_ERROR` | El servicio de prefirma de lotes XML devolvio un error | afirma-crypto-batch-client |
| `300702` | BatchErrorCode.ThirdParty | `XML_BATCH_POSTSIGN_ERROR` | El servicio de postfirma de lotes XML devolvio un error | afirma-crypto-batch-client |
| `400002` | SimpleErrorCode.Communication | `PROXY_CONNECTION` | Conexion incorrecta con proxy | afirma-simple |
| `400004` | ErrorCode.Communication | `INVALID_DOMAIN_SSL_CERTIFICATE_ERROR` | El certificado SSL no esta expedido para el dominio al que pertenece el servidor | afirma-core |
| `401100` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_SIGN_OPERATION` | Error en la descarga de la operacion de firma | afirma-simple |
| `401101` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_CERT_OPERATION` | Error en la descarga de la operacion de seleccion de certificado | afirma-simple |
| `401102` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_BATCH_OPERATION` | Error en la descarga de la operacion de lote | afirma-simple |
| `401103` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_SAVE_OPERATION` | Error en la descarga de la operacion de guardado de datos | afirma-simple |
| `401104` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_LOAD_OPERATION` | Error en la descarga de la operacion de carga de datos | afirma-simple |
| `401105` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION` | Error en la descarga de la operacion de firma y guardado | afirma-simple |
| `401106` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_SIGN_TIMEOUT` | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma | afirma-simple |
| `401107` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_CERT_TIMEOUT` | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de seleccion de certificados | afirma-simple |
| `401108` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_BATCH_TIMEOUT` | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma de lote | afirma-simple |
| `401109` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_SAVE_TIMEOUT` | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de guardado | afirma-simple |
| `401110` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_LOAD_TIMEOUT` | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de carga de datos | afirma-simple |
| `401111` | SimpleErrorCode.Communication | `RECIVING_DATA_OF_SIGN_AND_SAVE_TIMEOUT` | Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma y guardado | afirma-simple |
| `401200` | SimpleErrorCode.Communication | `SENDING_RESULT_OPERATION` | Error en el envio del resultado de la operacion | afirma-simple |
| `401201` | SimpleErrorCode.Communication | `SENDING_RESULT_TIMEOUT` | Se excedio el tiempo maximo de espera en la llamada al servicio de guardado del servidor intermedio | afirma-simple |
| `401300` | ErrorCode.Communication | `PRESIGN_SERVICE_CONNECTION_ERROR` | Error de conexion con el servidor trifasico al hacer la prefirma | afirma-core |
| `401301` | ErrorCode.Communication | `PRESIGN_SERVICE_COMMUNICATION_ERROR` | Error de comunicacion con el servidor trifasico al hacer la prefirma | afirma-core |
| `401302` | ErrorCode.Communication | `PRESIGN_SERVICE_TIMEOUT` | Se excedio el tiempo maximo de espera en la llamada a la prefirma del servidor trifasico | afirma-core |
| `401400` | ErrorCode.Communication | `POSTSIGN_SERVICE_CONNECTION_ERROR` | Error de conexion con el servidor trifasico al hacer la posfirma | afirma-core |
| `401401` | ErrorCode.Communication | `POSTSIGN_SERVICE_COMMUNICATION_ERROR` | Error de comunicacion con el servidor trifasico al hacer la posfirma | afirma-core |
| `401402` | ErrorCode.Communication | `POSTSIGN_SERVICE_TIMEOUT` | Se excedio el tiempo maximo de espera en la llamada a la postfirma del servidor trifasico | afirma-core |
| `401500` | BatchErrorCode.Communication | `JSON_BATCH_PRESIGN_CONNECTION_ERROR` | Error de conexion con el servidor trifasico al hacer la prefirma Batch JSON | afirma-crypto-batch-client |
| `401501` | BatchErrorCode.Communication | `JSON_BATCH_PRESIGN_COMMUNICATION_ERROR` | Error de comunicacion con el servidor trifasico al hacer la prefirma Batch JSON | afirma-crypto-batch-client |
| `401502` | BatchErrorCode.Communication | `JSON_BATCH_PRESIGN_TIMEOUT` | Se excedio el tiempo maximo de espera en la llamada a la prefirma de lote JSON del servidor trifasico | afirma-crypto-batch-client |
| `401600` | BatchErrorCode.Communication | `JSON_BATCH_POSTSIGN_CONNECTION_ERROR` | Error de conexion con el servidor trifasico al hacer la posfirma Batch JSON | afirma-crypto-batch-client |
| `401601` | BatchErrorCode.Communication | `JSON_BATCH_POSTSIGN_COMMUNICATION_ERROR` | Error de comunicacion con el servidor trifasico al hacer la posfirma Batch JSON | afirma-crypto-batch-client |
| `401602` | BatchErrorCode.Communication | `JSON_BATCH_POSTSIGN_TIMEOUT` | Se excedio el tiempo maximo de espera en la llamada a la postfirma de lote JSON del servidor trifasico | afirma-crypto-batch-client |
| `401700` | BatchErrorCode.Communication | `XML_BATCH_PRESIGN_CONNECTION_ERROR` | Error de conexion con el servidor trifasico al hacer la prefirma Batch XML | afirma-crypto-batch-client |
| `401701` | BatchErrorCode.Communication | `XML_BATCH_PRESIGN_COMMUNICATION_ERROR` | Error de comunicacion con el servidor trifasico al hacer la prefirma Batch XML | afirma-crypto-batch-client |
| `401702` | BatchErrorCode.Communication | `XML_BATCH_PRESIGN_TIMEOUT` | Se excedio el tiempo maximo de espera en la llamada a la prefirma de lote XML del servidor trifasico | afirma-crypto-batch-client |
| `401800` | BatchErrorCode.Communication | `XML_BATCH_POSTSIGN_CONNECTION_ERROR` | Error de conexion con el servidor trifasico al hacer la posfirma Batch XML | afirma-crypto-batch-client |
| `401801` | BatchErrorCode.Communication | `XML_BATCH_POSTSIGN_COMMUNICATION_ERROR` | Error de comunicacion con el servidor trifasico al hacer la posfirma Batch XML | afirma-crypto-batch-client |
| `401802` | BatchErrorCode.Communication | `XML_BATCH_POSTSIGN_TIMEOUT` | Se excedio el tiempo maximo de espera en la llamada a la postfirma de lote XML del servidor trifasico | afirma-crypto-batch-client |
| `410001` | ErrorCode.Communication | `TSA_CONNECTION_ERROR` | Error en la comunicacion con la autoridad de sellado de tiempo | afirma-core |
| `411001` | XMLErrorCode.Communication | `DERREFERENCING_DATA_ERROR` | No se han podido cargar de una URI los datos para la firma XML | afirma-crypto-core-xml |
| `420001` | SimpleErrorCode.Communication | `EXTERNAL_REQUEST` | Se ha realizado la peticion desde un puerto externo | afirma-simple |
| `420501` | SimpleErrorCode.Communication | `SENDING_RESULT_OPERATION_BY_SOCKET` | Error en el envio del resultado de la operacion por socket | afirma-simple |
| `420502` | SimpleErrorCode.Communication | `READING_FROM_SOCKET` | No se pudieron leer los datos del socket | afirma-simple |
| `500001` | ErrorCode.Functional | `CANCELLED_OPERATION` | Operacion cancelada por el usuario | afirma-core |
| `500002` | ErrorCode.Functional | `INVALID_SIGNATURE` | La firma que se trata de procesar es invalida | afirma-core |
| `500003` | ErrorCode.Functional | `INCOMPATIBLE_OPERATING_SYSTEM` | Sistema operativo no compatible con la operacion | afirma-core |
| `500004` | OOXMLErrorCode.Functional | `INCOMPATIBLE_JRE` | JRE no compatible con la operacion | afirma-crypto-ooxml |
| `500005` | SimpleErrorCode.Functional | `MINIMUM_VERSION_NON_SATISTIED` | La web solicito una version posterior de Autofirma | afirma-simple |
| `500006` | SimpleErrorCode.Functional | `SIGNER_REQUIREMENT_NOT_SUPPORTED` | El firmador hizo una peticion de datos no soportada | afirma-simple |
| `500007` | SimpleErrorCode.Functional | `VALIDATOR_REQUIREMENT_NOT_SUPPORTED` | El validador hizo una peticion de datos no soportada | afirma-simple |
| `501001` **(DUPLICATE CODE)** | ErrorCode.Functional | `CERTIFICATE_NEEDED` | Error en la operacion, no hay certificados | afirma-core |
| `501001` **(DUPLICATE CODE)** | SimpleErrorCode.Functional | `NO_CERTS_FOUND_SIGNING` | No se han encontrado certificados para realizar la seleccion | afirma-simple |
| `501002` | ErrorCode.Functional | `INVALID_FORMAT_FILE` | El formato de fichero no es valido para la operacion que se intenta realizar | afirma-core |
| `501003` | ErrorCode.Functional | `INVALID_SMARTCARD_PIN` | El PIN del la tarjeta inteligente es incorrecto | afirma-core |
| `501005` | ErrorCode.Functional | `DOCUMENT_TOO_LARGE` | El documento supera el tamano maximo permitido | afirma-core |
| `501006` | ErrorCode.Functional | `COMPATIBLE_SIGNATURE_NOT_FOUND` | La firma no es compatible con el formato de firma utilizado | afirma-core |
| `501007` | ErrorCode.Functional | `SIGNING_LTS` | Se esta intentando firmar una firma longeva que quedara invalidada | afirma-core |
| `501008` | ErrorCode.Functional | `SIGNING_WITH_POLICY_INCOMPATIBILITY` | La firma resultante sera incompatible con la politica de firma | afirma-core |
| `501009` | SimpleErrorCode.Functional | `CANT_IDENTIFY_SIGNATURE_FORMAT` | No se ha podido identificar un formato de firma para los datos | afirma-simple |
| `501010` | SimpleErrorCode.Functional | `VISIBLE_SIGNATURE_IS_MANDATORY` | La operacion marco como obligatoria la firma visible PDF | afirma-simple |
| `501011` | XMLErrorCode.Functional | `XPATH_NOT_FOUND` | Una o varias firmas incluidas en el documento no contienen un algoritmo XPath | afirma-crypto-core-xml |
| `502001` | SimpleErrorCode.Functional | `NO_CERTS_FOUND_SELECTING_CERT` | No se han encontrado certificados para realizar la seleccion | afirma-simple |
| `504001` | SimpleErrorCode.Functional | `NO_CERTS_FOUND_SIGNING_BATCH` | No se han encontrado certificados para realizar la firma del lote | afirma-simple |
| `506001` | MassiveErrorCode.Functional | `INDIR_NOT_FOUND` | El directorio de entrada no existe | afirma-core-massive |
| `506002` | MassiveErrorCode.Functional | `ACCESS_TO_DIR_IS_NOT_ALLOWED` | No se tiene acceso al directorio indicado | afirma-core-massive |
| `507001` | ValidationErrorCode.Functional | `INCOMPATIBLE_SIGNATURE` | El documento no esta firmado o la firma no es compatible | afirma-crypto-validation |
| `510001` | BinaryErrorCode.Functional | `SIGNATURE_DOESNT_CONTAIN_DATA` | La firma no contiene los datos firmados necesarios para la operacion | afirma-crypto-core-pkcs7 |
| `510002` | XMLErrorCode.Functional | `XML_DOCUMENT_NEEDED` | La firma requiere que los datos sean un documento XML | afirma-crypto-core-xml |
| `510003` | ODFErrorCode.Functional | `ODF_DOCUMENT_NEEDED` | La firma requiere que los datos sean un documento ODF | afirma-crypto-odf |
| `510004` | OOXMLErrorCode.Functional | `OOXML_DOCUMENT_NEEDED` | La firma requiere que los datos sean un documento OOXML | afirma-crypto-ooxml |
| `510005` | PdfErrorCode.Functional | `PDF_DOCUMENT_NEEDED` | La firma requiere que los datos sean un documento PDF | afirma-crypto-pdf-common |
| `510006` | ErrorCode.Functional | `SIGNING_MALFORMED_SIGNATURE` | La firma no es compatible o esta mal formada | afirma-core |
| `510007` | XMLErrorCode.Functional | `TRI_SIGNING_SIGNATURE` | No se permite firmar una firma XML en el modo de firma trifasica | afirma-crypto-core-xml |
| `510008` | XAdESErrorCode.Functional | `FACTURAE_ALREADY_SIGNED` | La factura ya tiene una firma electronica y no admite firmas adicionales | afirma-crypto-xades |
| `510009` | XAdESErrorCode.Functional | `FACTURAE_NEEDED` | La firma requiere que los datos sean FacturaE | afirma-crypto-xades |
| `511003` | ErrorCode.Functional | `KEYSTORE_LOCKED` | El almacen de claves esta bloqueado | afirma-core |
| `511004` | ErrorCode.Functional | `SMARTCARD_LOCKED` | La tarjeta inteligente esta bloqueada | afirma-core |
| `521000` | SimpleErrorCode.Functional | `POLICY_DEFAULT_ERROR` | Ha ocurrido un error configurando la politica | afirma-simple |
| `521001` | SimpleErrorCode.Functional | `INVALID_POLICY_IDENTIFIER` | El identificador de politica no puede ser nulo ni vacio | afirma-simple |
| `521002` | SimpleErrorCode.Functional | `INVALID_POLICY_IDENTIFIER_URI` | El identificador debe ser una URI valida | afirma-simple |
| `521003` | SimpleErrorCode.Functional | `MISSING_DIGEST_ALGORITHM` | Si se indica la huella digital es obligatorio indicar tambien el algoritmo | afirma-simple |
| `521004` | SimpleErrorCode.Functional | `UNREACHABLE_POLICY_IDENTIFIER_URI` | Si no se especifica la huella digital, el identificador debe ser una URI accesible | afirma-simple |
| `521005` | SimpleErrorCode.Functional | `INVALID_POLICY_IDENTIFIER_HASH_BASE64` | La huella digital debe estar en formato Base64 | afirma-simple |
| `521006` | SimpleErrorCode.Functional | `INVALID_POLICY_QUALIFIER_URI` | El calificador debe ser una URI valida | afirma-simple |
| `521007` | SimpleErrorCode.Functional | `INVALID_POLICY_IDENTIFIER_OID` | El identificador debe tener un formato OID valido | afirma-simple |
| `521008` | SimpleErrorCode.Functional | `EMPTY_POLICY_HASH` | La huella digital no puede ser nula ni vacia | afirma-simple |
| `521009` | SimpleErrorCode.Functional | `INVALID_POLICY_QUALIFIER_URL` | El calificador debe ser una URL valida | afirma-simple |
| `521010` | SimpleErrorCode.Functional | `INVALID_PROXY_CONFIG` | La configuracion de proxy no es valida | afirma-simple |
| `522001` | ConfiguratorErrorCode.Functional | `INVALID_CERTIFICATE_SIGNER` | El certificado firmante del fichero de configuracion no es valido | afirma-ui-simple-configurator-common |
| `522002` | ConfiguratorErrorCode.Functional | `INVALID_PREFERENCES_FILE_SIGNATURE` | La firma del fichero de configuracion no es valida | afirma-ui-simple-configurator-common |
| `522003` | ConfiguratorErrorCode.Functional | `INVALID_PREFERENCES_FILE_SIGNER` | El certificado firmante del fichero de configuracion no esta autorizado | afirma-ui-simple-configurator-common |
| `522004` | ConfiguratorErrorCode.Functional | `UNSIGNED_PREFERENCES_FILE` | No se permite la importacion de ficheros de preferencias sin firmar | afirma-ui-simple-configurator-common |
| `530001` | PluginManagerError.Functional | `MALFORMED_PLUGIN_SERVICE` | Se han encontrado plugins mal definidos en el fichero importado | afirma-simple-plugins-manager |
| `530002` | PluginManagerError.Functional | `NO_PLUGIN_FOUND` | No se encontro ningun plugin en los archivos | afirma-simple-plugins-manager |
| `530003` | PluginManagerError.Functional | `MULTIPLE_PLUGINS_FOUND` | No se permite la carga simultanea de varios plugins | afirma-simple-plugins-manager |
| `530004` | PluginManagerError.Functional | `BUTTON_NO_ACTION` | El plugin no ha definido accion para un boton | afirma-simple-plugins-manager |
| `530005` | PluginManagerError.Functional | `BUTTON_NO_WINDOW` | El plugin no ha definido la ventana en la que debe aparecer un boton | afirma-simple-plugins-manager |
| `530006` | PluginManagerError.Functional | `INVALID_ACTION_CLASS` | El plugin definio una clase de accion erronea | afirma-simple-plugins-manager |
| `530007` | SimpleErrorCode.Functional | `INVALID_PLUGIN_FILE` | El plugin no es valido para ser importado | afirma-simple |
| `530008` | PluginManagerError.Functional | `ALREADY_INSTALLED_PLUGIN` | El plugin ya se encuentra instalado | afirma-simple-plugins-manager |
| `530009` | SimpleErrorCode.Functional | `PLUGIN_FILE_NOT_FOUND` | No se ha encontrado el fichero del plugin | afirma-simple |
| `600002` | SimpleErrorCode.Request | `UNSUPPORTED_OPERATION` | La operacion no esta soportada | afirma-simple |
| `600009` | ErrorCode.Request | `UNSUPPORTED_CIPHER_KEY` | La clave de cifrado recibida no esta soportada | afirma-core |
| `600010` | ErrorCode.Request | `LOCAL_RETRIEVE_URL` | La URL del servlet de recuperacion no puede ser local | afirma-core |
| `600011` | KeyStoreErrorCode.Request | `UNSUPPORTED_KEYSTORE` | El almacen de claves solicitado no es compatible con el entorno de ejecucion | afirma-core-keystores |
| `600012` | ErrorCode.Request | `INVALID_READ_TIMEOUT` | El tiempo de espera de lectura de los servicios no es valido | afirma-core |
| `600100` | ErrorCode.Request | `DATA_NOT_FOUND` | No se ha recibido los datos en la peticion ni el id del fichero a descargar para la operacion de firma | afirma-core |
| `600101` | ErrorCode.Request | `RETRIEVE_URL_TO_SIGN_NOT_FOUND` | No se ha recibido la URL del servlet para descargar la informacion de la operacion de firma | afirma-core |
| `600102` | ErrorCode.Request | `STORAGE_URL_TO_SIGN_NOT_FOUND` | No se ha recibido la URL del servlet para guardar la firma en la operacion de firma | afirma-core |
| `600104` | ErrorCode.Request | `SIGNATURE_FORMAT_NOT_FOUND` | No se ha recibido el formato de firma para la operacion de firma | afirma-core |
| `600105` | ErrorCode.Request | `UNSUPPORTED_SIGNATURE_FORMAT` | El formato de firma indicado en la operacion de firma no esta soportado | afirma-core |
| `600106` | ErrorCode.Request | `SIGNATURE_ALGORITHM_NOT_FOUND` | No se ha recibido el algoritmo de firma para la operacion de firma | afirma-core |
| `600107` | ErrorCode.Request | `UNSUPPORTED_SIGNATURE_ALGORITHM` | El algoritmo de firma indicado en la operacion de firma no esta soportado | afirma-core |
| `600110` | ErrorCode.Request | `UNSUPPORTED_COUNTERSIGN_CONFIG` | No se soporta la configuracion de nodos a contrafirmar | afirma-core |
| `600111` | ErrorCode.Request | `UNSUPPORTED_POLICY_HASH_ALGORITHM` | El algoritmo de huella indicado en la politica de firma no esta soportado | afirma-core |
| `600112` | ErrorCode.Request | `INVALID_COUNTERSIGNATURE_INDEX` | El numero indicado no se corresponde con la posicion de ninguna contrafirma | afirma-core |
| `600113` | ErrorCode.Request | `INVALID_TIMESTAMP_HASH_ALGORITHM` | El algoritmo de huella para el sello de tiempo no esta soportado | afirma-core |
| `600114` | TriphaseErrorCode.Request | `MALFORMED_PRESIGN` | La prefirma recibida esta mal formada | afirma-server-triphase-signer-core |
| `600115` | TriServiceErrorCode.Request | `CRYPTO_OPERATION_NOT_FOUND` | No se ha recibido el identificador de operacion criptografica para la operacion de firma | afirma-server-triphase-signer |
| `600116` **(DUPLICATE CODE)** | ErrorCode.Request | `INVALID_RETRIEVE_URL_TO_SIGN` | La URL del servlet de descarga para la operacion de firma esta mal formado | afirma-core |
| `600116` **(DUPLICATE CODE)** | TriServiceErrorCode.Request | `UNSUPPORTED_CRYPTO_OPERATION` | El identificador de operacion criptografica no es valido | afirma-server-triphase-signer |
| `600117` | ErrorCode.Request | `RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL` | La URL del servlet de descarga para la operacion de firma no puede ser local | afirma-core |
| `600118` | ErrorCode.Request | `INVALID_STORAGE_URL_TO_SIGN` | La URL del servlet de guardado para la operacion de firma esta mal formada | afirma-core |
| `600119` | ErrorCode.Request | `LOCAL_STORAGE_URL_TO_SIGN` | La URL del servlet de guardado para la operacion de firma no puede ser local | afirma-core |
| `600120` | ErrorCode.Request | `INVALID_SESSION_ID_TO_SIGN` | El id de sesion recibido para la firma no es valido | afirma-core |
| `600121` | SimpleErrorCode.Request | `INVALID_FORMAT_SIGNATURE_PARAM` | Alguna de las propiedades de firma es incorrecta | afirma-simple |
| `600200` | ErrorCode.Request | `STORAGE_URL_TO_SELECT_CERT_NOT_FOUND` | No se ha recibido la URL del servlet para guardar el certificado en la operacion de enviar certificado | afirma-core |
| `600201` | ErrorCode.Request | `INVALID_SESSION_ID_TO_SELECT_CERT` | El id de sesion recibido para la seleccion de certificado no es valido | afirma-core |
| `600202` | ErrorCode.Request | `INVALID_STORAGE_URL_TO_SELECT_CERT` | La URL del servlet de guardado para la operacion de seleccion de certificado esta mal formada | afirma-core |
| `600203` | ErrorCode.Request | `LOCAL_STORAGE_URL_TO_SELECT_CERT` | La URL del servlet de guardado para la operacion de seleccion de certificado no puede ser local | afirma-core |
| `600300` | ErrorCode.Request | `DATA_TO_SAVE_NOT_FOUND` | No se ha recibido los datos en la peticion ni el id del fichero a descargar para la operacion de guardado | afirma-core |
| `600301` | ErrorCode.Request | `RETRIEVE_URL_TO_SAVE_NOT_FOUND` | No se ha recibido la URL del servlet para descargar la informacion de la operacion de guardado | afirma-core |
| `600302` | ErrorCode.Request | `STORAGE_URL_TO_SAVE_NOT_FOUND` | No se ha recibido la URL del servlet para guardar la firma en la operacion de guardado | afirma-core |
| `600303` | ErrorCode.Request | `INVALID_SESSION_ID_TO_SAVE` | El id de sesion recibido para el guardado de datos no es valido | afirma-core |
| `600304` | ErrorCode.Request | `INVALID_STORAGE_URL_TO_SAVE` | La URL del servlet de guardado para la operacion de guargado esta mal formada | afirma-core |
| `600305` | ErrorCode.Request | `LOCAL_STORAGE_URL_TO_SAVE` | La URL del servlet de guardado para la operacion de guardado no puede ser local | afirma-core |
| `600306` | ErrorCode.Request | `FILENAME_TO_SAVE_NOT_FOUND` | No se ha recibido el nombre por defecto para el fichero de datos a guardar | afirma-core |
| `600307` | ErrorCode.Request | `FILE_EXTENSION_TO_SAVE_NOT_FOUND` | No se ha recibido la extension por defecto para el fichero de datos a guardar | afirma-core |
| `600402` | ErrorCode.Request | `STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND` | No se ha recibido la URL del servlet para guardar la firma en la operacion de firma de lotes | afirma-core |
| `600403` | ErrorCode.Request | `ID_SESSION_TO_SIGN_BATCH_NOT_FOUND` | No se ha recibido el id del fichero a guardar para la operacion de firma de lotes | afirma-core |
| `600405` | ErrorCode.Request | `PRESIGN_BATCH_URL_NOT_FOUND` | No se ha recibido el URL de prefirma de la firma de lotes | afirma-core |
| `600406` | ErrorCode.Request | `POSTSIGN_BATCH_URL_NOT_FOUND` | No se ha recibido el URL de postfirma de la firma de lotes | afirma-core |
| `600410` | ErrorCode.Request | `INVALID_SESSION_ID_TO_SIGN_BATCH` | El id de sesion recibido no es valido | afirma-core |
| `600411` | ErrorCode.Request | `INVALID_STORAGE_URL_TO_SIGN_BATCH` | La URL del servlet de guardado para la operacion de firma de lotes esta mal formada | afirma-core |
| `600412` | ErrorCode.Request | `LOCAL_STORAGE_URL_TO_SIGN_BATCH` | La URL del servlet de guardado para la operacion de firma de lotes no puede ser local | afirma-core |
| `600413` | ErrorCode.Request | `INVALID_PRESIGN_BATCH_URL` | La URL de prefirma de la firma de lotes esta mal formada | afirma-core |
| `600414` | ErrorCode.Request | `LOCAL_PRESIGN_BATCH_URL` | La URL de prefirma de la firma de lotes no puede ser local | afirma-core |
| `600415` | ErrorCode.Request | `INVALID_POSTSIGN_BATCH_URL` | La URL de postfirma de la firma de lotes esta mal formada | afirma-core |
| `600416` | ErrorCode.Request | `LOCAL_POSTSIGN_BATCH_URL` | La URL de postfirma de la firma de lotes no puede ser local | afirma-core |
| `600417` | BatchErrorCode.Request | `INVALID_PARAMS_TO_PRESIGN_JSON_BATCH` | El servicio de prefirma de lote JSON informo de un error en los parametros enviados | afirma-crypto-batch-client |
| `600418` | BatchErrorCode.Request | `INVALID_PARAMS_TO_POSTSIGN_JSON_BATCH` | El servicio de postfirma de lote JSON informo de un error en los parametros enviados | afirma-crypto-batch-client |
| `600419` | BatchErrorCode.Request | `MALFORMED_JSON_BATCH` | El lote no es un JSON valido o esta mal formado | afirma-crypto-batch-client |
| `600420` | SimpleErrorCode.Request | `INVALID_FORMAT_SIGN_BATCH_PARAM` | Alguna de las propiedades de firma del lote es incorrecta | afirma-simple |
| `600501` | BatchErrorCode.Request | `INVALID_PARAMS_TO_PRESIGN_XML_BATCH` | El servicio de prefirma de lote XML informo de un error en los parametros enviados | afirma-crypto-batch-client |
| `600502` | BatchErrorCode.Request | `INVALID_PARAMS_TO_POSTSIGN_XML_BATCH` | El servicio de postfirma de lote XML informo de un error en los parametros enviados | afirma-crypto-batch-client |
| `600503` | BatchErrorCode.Request | `MALFORMED_XML_BATCH` | El lote no es un XML valido o esta mal formado | afirma-crypto-batch-client |
| `600601` | MassiveErrorCode.Request | `DECODING_HASH_ERROR` | Se ha proporcionado un hash no valido para la firma explicita | afirma-core-massive |
| `600701` | ErrorCode.Request | `INVALID_PARAMS_TO_PRESIGN` | El servicio de prefirma informo de un error en los parametros enviados | afirma-core |
| `600702` | ErrorCode.Request | `INVALID_PARAMS_TO_POSTSIGN` | El servicio de postfirma informo de un error en los parametros enviados | afirma-core |
| `610001` | XMLErrorCode.Request | `INVALID_ENCODING_URI` | La URI del algoritmo de codificacion no es valida | afirma-crypto-core-xml |
| `610002` | XMLErrorCode.Request | `INVALID_REFERENCES_HASH_ALGORITHM_URI` | La URI del algoritmo de huella de las referencias no es valida | afirma-crypto-core-xml |
| `610003` | XMLErrorCode.Request | `INVALID_CANONICALIZATION_URI` | La URI del algoritmo de canonicalizacion no es valida | afirma-crypto-core-xml |
| `610004` | XMLErrorCode.Request | `INVALID_PRECALCULATED_DATA_HASH_ALGORITHM` | El algoritmo de huella de los datos precalculados no es valido | afirma-crypto-core-xml |
| `610005` | XMLErrorCode.Request | `INVALID_TRANSFORMATION` | La transformacion no es valida | afirma-crypto-core-xml |
| `610006` | XMLErrorCode.Request | `INVALID_REFERENCE_URI` | La URI a los datos firmados no es valida | afirma-crypto-core-xml |
| `610007` | XMLErrorCode.Request | `INVALID_NODE_SELECTOR_XPATH` | La ruta XPATH para la seleccion de nodo no es valida | afirma-crypto-core-xml |
| `610201` | XAdESErrorCode.Request | `REFERENCE_HASH_NOT_FOUND` | No se ha indicado la huella digital de una referencia a los datos firmados | afirma-crypto-xades |
| `610202` | XAdESErrorCode.Request | `INVALID_REFERENCE_HASH` | Error al decodificar el hash de los datos referenciados | afirma-crypto-xades |
| `610203` | XAdESErrorCode.Request | `MANIFEST_REFERENCES_NOT_FOUND` | No se han proporcionado referencias para el manifest de firma | afirma-crypto-xades |
| `610204` | XAdESErrorCode.Request | `INVALID_DATA_REFERENCE_URI` | La URI a los datos firmados no es valida | afirma-crypto-xades |
| `610301` | PdfErrorCode.Request | `INVALID_SIGNATURE_POSITION` | La posicion para la firma visible en la pagina no es valida | afirma-crypto-pdf-common |
| `610302` | PdfErrorCode.Request | `INVALID_SIGNATURE_PAGE` | La pagina para la firma visible no es valida | afirma-crypto-pdf-common |
| `620009` | SimpleErrorCode.Request | `UNSUPPORTED_REQUEST_SCHEME` | El esquema de la URL de invocacion no esta soportado | afirma-simple |
| `620010` | SimpleErrorCode.Request | `INVALID_SESSION_ID` | El identificador de sesion del websocket es incorrecto | afirma-simple |
| `620011` | SimpleErrorCode.Request | `UNSUPPORTED_PROTOCOL_VERSION` | Version de protocolo de comunicacion con el navegador no soportada | afirma-simple |
| `620012` | SimpleErrorCode.Request | `REQUEST_URI_NOT_FOUND` | No se ha proporcionado la URI de invocacion | afirma-simple |
| `620013` | SimpleErrorCode.Request | `PORTS_NOT_FOUND` | No se han proporciona los puertos de conexion | afirma-simple |
| `620016` | SimpleErrorCode.Request | `MALFORMED_REQUEST_TO_SOCKET` | Los parametros recibidos en el socket no son correctos | afirma-simple |

### 10.7 User-facing texts per code (`afirma-simple` `protocolmessages_es_ES.properties`)

Lookup: `Error.<code>`, else category fallback (§10.5). Other locales: `ca_ES, en_US, eu_ES, gl_ES, va_ES` files alongside.

| Message key | User-facing text (es_ES, exact; \n = line break) |
|---|---|
| `Error` | Se ha encontrado un error durante la operaci&oacute;n. |
| `Error.1XXXXX` | Se ha producido un error con el dispositivo externo. No se puede completar la operación.  |
| `Error.2XXXXX` | Ocurrió un error interno durante la operación  |
| `Error.220001` | Autofirma no ha podido comunicarse con el navegador web. Reintente la operación o restaure\nla instalación de Autofirma si el problema persiste. |
| `Error.220008` | No se han encontrado las claves para la conexión segura con el navegador.\nEjecute la función de restauración de la instalación desde el menú de herramientas de Autofirma para poder firmar. |
| `Error.3XXXXX` | Un servicio o biblioteca externo devolvió un error durante el proceso. Se aborta la operación. |
| `Error.4XXXXX` | Ocurrió un error al conectarse con un servicio o aplicativo externo. Se aborta la operación. |
| `Error.400004` | Se ha interrumpido la operación al detectar una conexión con un entorno no seguro: %0 |
| `Error.5XXXXX` | No se ha podido completar la operación. |
| `Error.500006` | La firma requiere información que Autofirma no ha podido identificar. Compruebe si existe una versión más reciente de Autofirma. |
| `Error.500007` | La validación de la firma requiere información que Autofirma no ha podido identificar. Compruebe si existe una versión más reciente de Autofirma. |
| `Error.500002` | La firma que se trata de procesar es inválida. |
| `Error.500003` | Su sistema operativo no es compatible con la operación solicitada. |
| `Error.500004` | Su JRE no es compatible con la operación solicitada. Actualícela a la última versión compatiple. |
| `Error.500005` | La aplicación web requiere una versión posterior de Autofirma. Actualicese a la última versión disponible. |
| `Error.500008` | La operación de carga de fichero no está disponible en este sistema. |
| `Error.500009` | La operación de carga de múltiples ficheros no está disponible en este sistema. |
| `Error.501001` | No se han encontrado certificados para realizar la firma. |
| `Error.501002` | El formato de fichero no es válido para la operación que se intenta realizar. |
| `Error.501003` | El PIN del la tarjeta inteligente es incorrecto. |
| `Error.501005` | El documento supera el tamaño máximo permitido. |
| `Error.501006` | La firma no es compatible con el formato de firma utilizado. |
| `Error.501007` | No se agregará la nueva firma porque la firma longeva original quedaría invalidada. |
| `Error.501008` | No se firmará el documento porque la firma resultante sería incompatible con la política de firma. |
| `Error.501009` | No se ha podido identificar un formato de firma para los datos. |
| `Error.501010` | Sólo se permite la firma visible del documento PDF. |
| `Error.502001` | No se han encontrado certificados para realizar la selección. |
| `Error.504001` | No se han encontrado certificados para realizar la firma del lote. |
| `Error.506001` | El directorio de entrada no existe. |
| `Error.506002` | No se tiene acceso al directorio indicado. |
| `Error.510001` | La firma no contiene los datos firmados necesarios para completar la operación. |
| `Error.510002` | Para poder realizar esta operación es necesario seleccionar un fichero XML. |
| `Error.510003` | Para poder realizar esta operación es necesario seleccionar un fichero ODF. |
| `Error.510004` | Para poder realizar esta operación es necesario seleccionar un fichero OOXML. |
| `Error.510005` | Para poder realizar esta operación es necesario seleccionar un fichero PDF. |
| `Error.510006` | La firma no es compatible o está mal formada. |
| `Error.510007` | El documento es una firma XML y no se puede volver a firmar. Pruebe a cofirmarla o contrafirmarla. |
| `Error.510008` | La factura ya tiene una firma electrónica y no admite firmas adicionales. |
| `Error.510009` | Para poder realizar esta operación es necesario seleccionar un fichero FacturaE. |
| `Error.511003` | El almacén de claves esta bloqueado. |
| `Error.511004` | La tarjeta inteligente esta bloqueada. |
| `Error.6XXXXX` | Los parámetros recibidos no son corretos. |
| `Error.62XXXX` | La petición no es válida. |
| `Error.620011` | La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible. |

---

## 11. Validation (`afirma-crypto-validation`)

### 11.1 Result model — `SignValidity`

* `SIGN_DETAIL_TYPE`: `OK`, `KO`, `UNKNOWN`, `PENDING_CONFIRM_BY_USER`, `GENERATED`.
* `VALIDITY_ERROR` (cause; may be `null`): `NO_DATA, CORRUPTED_SIGN, NO_MATCH_DATA, NO_SIGN, CERTIFICATE_PROBLEM, CERTIFICATE_EXPIRED, CERTIFICATE_NOT_VALID_YET, CANT_VALIDATE_CERT, ALGORITHM_NOT_SUPPORTED, CA_NOT_SUPPORTED, CRL_PROBLEM, PDF_UNKOWN_VALIDITY, OOXML_UNKOWN_VALIDITY, ODF_UNKOWN_VALIDITY, UNKOWN_ERROR, UNKOWN_SIGNATURE_FORMAT, MODIFIED_FORM, MODIFIED_DOCUMENT, OVERLAPPING_SIGNATURE, SUSPECTED_SIGNATURE, SIGN_PROFILE_NOT_CHECKED, CANT_VALIDATE_EXTERNALLY_DETACHED, BAD_BUILD_SIGN, CERTIFIED_SIGN_REVISION` (spelling `UNKOWN` is in the enum names).
* Fields: `validity`, `error`, `errorException` (nullable), `errorCode` (from ctor, or from the exception if it is an `AOControlledException`).
* `toString()` = `validityTypeToString()` + (`error != null` ? `": " + message(error)` : ""). `validityTypeToString()`: OK/GENERATED → msg 0, UNKNOWN → 1, PENDING_CONFIRM_BY_USER → 2, KO → 3.
* Message keys `SignValidationMessage.N` (`validationmessages_es_ES.properties`):

| N | es_ES text | used for |
|---|---|---|
| 0 | Firma válida | OK / GENERATED |
| 1 | Validación incompleta | UNKNOWN |
| 2 | Validez a confirmar por el usuario | PENDING_CONFIRM_BY_USER |
| 3 | Firma no válida | KO |
| 4 | no se puede comprobar la validez por no tener los datos firmados | NO_DATA |
| 5 | la informaci&oacute;n contenida en la firma no es consistente (certificados corruptos, etc.) | CORRUPTED_SIGN |
| 6 | la firma no se corresponde con los datos firmados | NO_MATCH_DATA |
| 7 | no se encuentra la firma dentro del documento | NO_SIGN |
| 8 | no se puede extraer un certificado o este no es v&aacute;lido | CERTIFICATE_PROBLEM |
| 9 | existe un certificado de firma caducado | CERTIFICATE_EXPIRED |
| 10 | existe un certificado de firma que aun no es v&aacute;lido | CERTIFICATE_NOT_VALID_YET |
| 11 | no se ha podido validar el certificado correctamente | CANT_VALIDATE_CERT |
| 12 | la firma contiene un algoritmo no reconocido o no soportado | ALGORITHM_NOT_SUPPORTED |
| 13 | no se soporta la CA de expedici&oacute;n | CA_NOT_SUPPORTED |
| 14 | existe algun problema con las CRLs incrustadas en la firma | CRL_PROBLEM |
| 15 | no se puede comprobar la validez de la firma PDF | PDF_UNKOWN_VALIDITY |
| 16 | no se puede comprobar la validez de la firma OOXML | OOXML_UNKOWN_VALIDITY |
| 17 | no se puede comprobar la validez de la firma ODF | ODF_UNKOWN_VALIDITY |
| 18 | no se puede comprobar la validez de la firma | UNKOWN_ERROR |
| 19 | los datos proporcionados no se corresponden con ning&uacute;n formato de firma reconocido | UNKOWN_SIGNATURE_FORMAT |
| 20 | el documento PDF es sospechoso de haberse modificado tras la firma | MODIFIED_DOCUMENT |
| 21 | las firmas del documento se solapan pudiendo ocultar informaci&oacute;n | OVERLAPPING_SIGNATURE |
| 22 | un formulario del documento fue modificado tras la firma | MODIFIED_FORM |
| 23 | el documento es sospechoso y el usuario debe revisar la firma | SUSPECTED_SIGNATURE |
| 24 | la firma contiene atributos longevos que Autofirma no puede validar. Para una validaci&oacute;n completa recurra a VALIDe. | SIGN_PROFILE_NOT_CHECKED |
| 25 | no se permite la validaci&oacute;n de firmas con referencias externas | CANT_VALIDATE_EXTERNALLY_DETACHED |
| 26 | la firma no est&aacute; correctamente formada | BAD_BUILD_SIGN |
| 27 | El documento certificado no permit&iacute;a nuevas firmas | CERTIFIED_SIGN_REVISION |

(HTML entities are literally in the bundle; the UI renders them as HTML.)

### 11.2 `SignValider` API

```
abstract class SignValider {
  relaxed: bool (default false)           // relaxed => throw RuntimeConfigNeededException instead of KO for user-decidable issues
  List<SignValidity> validate(byte[] sign)
  List<SignValidity> validate(byte[] sign, boolean checkCertificates)
  List<SignValidity> validate(byte[] sign, Properties params)
}
```
The **first** element of the list is the overall verdict shown to the user; callers typically use `validate(...).get(0)`.

Post-processing helpers:
* `checkValidityKOPriority(list)`: rebuild list, KO items inserted at the front (in reverse encounter order), others appended; duplicates removed by identity.
* `checkLongStandingValiditySign(list)`: if the list contains a KO `CERTIFICATE_EXPIRED`, an `UNKNOWN SIGN_PROFILE_NOT_CHECKED`, and **no other KO**, swap the `SIGN_PROFILE_NOT_CHECKED` item into position 0 (expired cert in a long-term signature is downgraded to "incomplete validation").

### 11.3 Validator selection (`SignValiderFactory`)

* `getSignValider(byte[] data)`: empty/null → `IllegalArgumentException("No se han indicado datos de firma")`. Order: `isPDF` → `ValidatePdfSignature`; `isFacturae` → `ValidateXMLSignature`; `isXML` → `ValidateXMLSignature`; `isOOXML` → `null` (warn "No hay un validador para OOXML"); `isODF` → `null`; else → `ValidateBinarySignature`.
* `getSignValider(AOSigner)`: `AOCAdESSigner` → binary; `AOXAdESSigner` or `AOFacturaESigner` → XML; `AOPDFSigner` → PDF; anything else (CMS, XMLDSig, ASiC, ODF, OOXML, tri-phase signers, NONE) → `null`.

### 11.4 `ValidateBinarySignature` (CMS/CAdES)

`validate(sign[, data][, checkCertificates=true])` (the `Properties` overload ignores params, checks certs):
1. Not `AOCAdESSigner.isSign` and not `AOCMSSigner.isSign` → `[KO NO_SIGN]`.
2. `signedData = data ?: signer.getData(sign)`; null → add `UNKNOWN NO_DATA`; `AOInvalidSignatureFormatException` → add `KO NO_SIGN(e)`; other `AOException` → add `KO UNKOWN_ERROR`.
3. For each SignerInfo (top-level only; countersignatures not validated): profile = `resolveASN1Format` (§11.7). Find the cert by SignerId in the CMS certificate set; if `checkCertificates` check validity **now** against the current time (`checkValidity()`): expired → `KO CERTIFICATE_EXPIRED`, not yet valid → `KO CERTIFICATE_NOT_VALID_YET`; verify the signature (signed attributes / content digest) with BouncyCastle: digest mismatch → `KO NO_MATCH_DATA` **only if** the CMS has embedded content (detached-without-data mismatches are ignored); signature false or other error → `KO CANT_VALIDATE_CERT`. Profile not in {`CAdES-BES`, `No reconocido`, `CAdES B-Level`, `CAdES B-B-Level`, `CMS`, `CAdES-EPES`} → `UNKNOWN SIGN_PROFILE_NOT_CHECKED`. Nothing added → `OK`. UNKNOWN items are inserted at the front, others appended.
4. Errors building CMS: `CMSSignerDigestMismatchException` → `KO NO_MATCH_DATA`; other → `KO (error=null)`.
5. Apply `checkValidityKOPriority`, then `checkLongStandingValiditySign`.
No chain building, no revocation, no trust anchors — only cryptographic integrity + validity period.

### 11.5 `ValidatePdfSignature`

Params (extraParams keys): `headless`, `checkCertificates` (only via the boolean overload; the `Properties` overload defaults to **not** checking cert dates since the key is absent → false), `allowModifiedForm` (`allowSignModifiedForm`), `allowShadowAttack`, `pagesToCheckShadowAttack` (default `"10"`, or `all`), PDF password params (PDF spec).
1. Open PDF; no signatures or error → `[KO NO_SIGN code 507001]`.
2. **Form modification**: if `allowModifiedForm` not true and revisions > 1: compare AcroForm field values (excluding `/Sig` fields, plus widget annotations not declared, named by `/T` or `P<page>A<index>`) between the revision covered by the **oldest** signature and the final document; any difference → if `relaxed`: throw `PdfFormModifiedException` (RuntimeConfigNeeded, `denied = (allowModifiedForm was set)`); else add `KO MODIFIED_FORM`.
3. **PDF Shadow Attack** (skipped if forms are allowed, if a form change was found, if `allowShadowAttack=true`, or if there is no revision after the newest signature): for pages `i = 0..n-1` (n = `pagesToCheck` parsed as int, or the page count for `all`): (a) overlap test on the **current** document's page annotations — for each annotation index `j` < count-1 that is a widget with non-zero width and height, it is "overlapping" iff **every** annotation after it (`j+1..end`, any type) intersects its rectangle (closed intervals); the scan then skips `j+1` (loop index pre-incremented); overlap → `PENDING_CONFIRM_BY_USER OVERLAPPING_SIGNATURE`; (b) render page `i` of the current document and of the newest signed revision with PDFBox at 40 DPI, `ImageType.GRAY`; different dimensions or any differing pixel → `PENDING_CONFIRM_BY_USER MODIFIED_DOCUMENT`. First finding returned. Any exception (e.g. `n` greater than the page count) aborts the check silently with "no finding" (pages already compared still count). If found: relaxed and `allowShadowAttack` absent → throw `SuspectedPSAException` (RuntimeConfigNeeded); else convert PENDING → `KO` with same cause and add.
4. Per signature: profile = `resolvePDFFormat(whole PDF)` (§11.7, computed once from the newest signature). `pk.getStrictHashAlgorithm()==null` → `KO ALGORITHM_NOT_SUPPORTED`; unless SubFilter is `ETSI.RFC3161` or `DocTimeStamp`: `!verify()` → `KO NO_MATCH_DATA`, exception → `KO CORRUPTED_SIGN`; if checkCert: expired / not yet valid (vs. now); profile not in {`PAdES-Basic`, `No reconocido`, `PAdES-BES`, `PAdES B-Level`, `PAdES B-B-Level`, `PAdES-EPES`} → `UNKNOWN SIGN_PROFILE_NOT_CHECKED`. Merge: UNKNOWN to front, non-OK appended.
5. Certification level 1 (no changes allowed) and no issues so far: find the certifying signature (has `/Reference` with `/TransformMethod`), and every signature with a later revision → `KO CERTIFIED_SIGN_REVISION`.
6. KO priority, long-standing swap; empty → `[OK]`.

### 11.6 `ValidateXMLSignature` (XAdES/XMLDSig/FacturaE)

`validate(sign[, checkCertificates=true])` (`Properties` overload ignores params and checks certs):
1. Secure DOM parse failure → `[KO NO_SIGN]`; no `ds:Signature` element → `[KO NO_SIGN]`.
2. For each `ds:Signature` (all, including nested countersignatures and timestamp-embedded ones): JSR-105 validation with a key selector taking the first `KeyValue` public key, else the first certificate in `X509Data`; custom URI dereferencer (resolves `#id` references inside the document; external references fail). `signature.validate()` false → `KO NO_MATCH_DATA` (once per document); `SignatureValue.validate()` false → same (once); every failing `Reference` → another `KO NO_MATCH_DATA` (not de-duplicated). If checkCertificates: every certificate in KeyInfo/X509Data is checked against the current time → `KO CERTIFICATE_EXPIRED` (once per document) / `KO CERTIFICATE_NOT_VALID_YET` (per occurrence). Profile (`resolveSignerXAdESFormat`) not in {`XAdES B-Level`, `No reconocido`, `XAdES B-B-Level`, `XAdES-BES`, `XAdES-EPES`} → `UNKNOWN SIGN_PROFILE_NOT_CHECKED`.
3. `XMLSignatureException` → `KO BAD_BUILD_SIGN`; other exception → `UNKNOWN UNKOWN_ERROR` (processing stops).
4. Only `checkLongStandingValiditySign` (**no** KO-priority reordering); empty → `[OK]`.
`validateSign(Element, profile, isExternalDetached)` (used by the details view): externally detached → `[UNKNOWN CANT_VALIDATE_EXTERNALLY_DETACHED]`.

### 11.7 Signature profile detection (`ISignatureFormatDetector` constants, used to decide `SIGN_PROFILE_NOT_CHECKED`)

Constants: `No reconocido`, `CAdES-A`, `CAdES-XL1`, `CAdES-XL2`, `CAdES-X1`, `CAdES-X2`, `CAdES-C`, `CAdES-T`, `CAdES-EPES`, `CAdES-BES`, `CMS`, `CMS-T`, `XAdES-A`, `XAdES-XL1`, `XAdES-XL2`, `XAdES-X1`, `XAdES-X2`, `XAdES-C`, `XAdES-T`, `XAdES-EPES`, `XAdES-BES`, `PDF`, `PAdES-Basic`, `PAdES-BES`, `PAdES-EPES`, `PAdES-LTV`, `CAdES B-Level`, `CAdES B-B-Level`, `CAdES T-Level`, `CAdES LT-Level`, `CAdES LTA-Level`, `XAdES B-Level`, `XAdES B-B-Level`, `XAdES T-Level`, `XAdES LT-Level`, `XAdES LTA-Level`, `PAdES B-Level`, `PAdES B-B-Level`, `PAdES T-Level`, `PAdES LT-Level`, `PAdES LTA-Level`, `ASiC-S B-Level`, `ASiC-S T-Level`, `ASiC-S LT-Level`, `ASiC-S LTA-Level`, `CADES`, `PKCS7`.

* **CMS SignerInfo** (`resolveASN1Format`), first match wins:
  1. no signed `signingCertificate` (`1.2.840.113549.1.9.16.2.12`), `signingCertificateV2` (`…2.47`) nor `otherSigCert` (`…2.19`) → `CMS`, or `CMS-T` if the unsigned attr `signatureTimeStampToken` (`…2.14`) exists;
  2. signed `sigPolicyId` (`…2.15`) → `CAdES-EPES`; if signed `signingTime` → `CAdES B-Level` → (+timestamp) `CAdES T-Level` → (+ no certificateRefs/revocationRefs/attrCertRefs/attrRevocationRefs/escTimeStamp/certCRLTimestamp/certValues/revocationValues/archiveTimestamp(V1/V2)/longTermValidation unsigned attrs **and** ≥1 CRL in the SignedData) `CAdES LT-Level` → (+ `archiveTimestampV3` `0.4.0.1733.2.4`) `CAdES LTA-Level`; without signingTime: `CAdES-T` if timestamped;
  3. has signingCertificate/V2/otherSigCert → `CAdES-BES`; if signed `signingTime` → `CAdES B-Level` → T/LT/LTA exactly as above; without signingTime it stays `CAdES-BES` even if timestamped;
  4. (`signingCertificateV2` → `CAdES B-B-Level` — unreachable, step 3 already matches.)
  Any exception (e.g. no signed attributes) → `No reconocido`.
* **PDF** (`resolvePDFFormat`): newest non-timestamp signature dictionary. `ETSI.CAdES.detached` + `/M` + signed `signingCertificate` → `PAdES B-Level`; with `signingCertificateV2` → `PAdES B-B-Level`; then LTA (≥2 signature timestamps or ≥2 DocTimeStamps, plus a DSS dictionary in the doc or any revision) / LT (exactly one TS or one DocTimeStamp + DSS) / T (exactly one TS xor one DocTimeStamp). Otherwise: DSS or any DocTimeStamp → `PAdES-LTV`; else `PAdES-EPES` (CAdES subfilter + policy in any signer/countersigner), `PAdES-BES` (CAdES subfilter, first signer without policy), `PAdES-Basic` (`adbe.pkcs7.detached`/`adbe.pkcs7.sha1`), `PDF` (other subfilters).
* **XAdES** (`resolveSignerXAdESFormat`, only namespace `http://uri.etsi.org/01903/v1.3.2#`): `SignaturePolicyIdentifier` → EPES, else `QualifyingProperties` → BES, else `No reconocido`. Then baseline: `XAdES B-Level` if no `QualifyingPropertiesReference` and `SigningTime` + `SigningCertificate` + `DataObjectFormat/MimeType`; → `T-Level` (SignatureTimeStamp) → `LT-Level` → `LTA-Level` (ArchiveTimeStamp); else `XAdES B-B-Level` with `SigningCertificateV2` (**never upgraded to T/LT/LTA**, so timestamped B-B signatures pass the profile check). If still EPES/BES, non-baseline upgrades in order `XAdES-A`, `-XL1`, `-XL2`, `-X1`, `-X2`, `-C`, `-T`.
* **Consequence**: any signature with a timestamp or long-term data (T, LT, LTA, CMS-T, CAdES-T, XAdES-T, PAdES-LTV, …) is reported as `UNKNOWN SIGN_PROFILE_NOT_CHECKED` ("Validación incompleta… recurra a VALIDe"). XAdES 1.2.2/1.1.1 signatures are `No reconocido` and pass the profile check.

---

## 12. Signers tree model

### 12.1 `AOTreeNode` / `AOTreeModel` / `AOTreeUtil`

* `AOTreeNode { parent, children: List (lazy), userObject }`; `add(child)` appends (re-parenting: removed from old parent; adding a node already a child of this node moves it to the end); adding an ancestor → `IllegalArgumentException("El nuevo hijo es ya un ancestro")`; `null` → IAE. `getChildAt(i)` on a leaf → `ArrayIndexOutOfBoundsException("El nodo no tiene hijos")`. `isLeaf()` = no children. `toString()` = `userObject.toString()` or `"null"`.
* `AOTreeModel(root)`; `getRoot()`; static `getChild(parent, i)`, `getChildCount(parent)`.
* Shape returned by `getSignersStructure`: root `AOTreeNode("Datos")` (ODF returns an empty tree with root `"Raíz"` when an exception occurs); children = top-level signatures (signatures and cosignatures, in document order); each node's children = its countersignatures (recursive). CMS/CAdES ignore timestamp/long-term unsigned attributes when looking for countersignatures (`signatureTimeStampToken`, `archiveTimestamp(V2/V3=0.4.0.1733.2.4)`, `escTimeStamp`, revocation/cert refs/values, `longTermValidation 0.4.0.1733.2.2`).
* `AOTreeUtil.showTreeAsString(tree, linePrefix=null→"", indent=null→"\t")`: for each root child, DFS: `"\n" + linePrefix + indent*depth + userObject`. Empty/invalid tree → `null`.

### 12.2 `AOSimpleSignInfo` (node payload when `asSimpleSignInfo=true`)

| Field | Type | Set by signers | Meaning |
|---|---|---|---|
| `certs` | `X509Certificate[]` (non-empty, `[0]` non-null, else IAE `"No se ha introducido la cadena de certificacion"`) | yes | CMS/CAdES: `[signerCert]` only — found in the SignedData certificate set by **serial number only** (SignerIdentifier assumed IssuerAndSerialNumber); if not found the empty array makes the constructor throw and the whole `getSignersStructure` fails. XML: every `ds:X509Certificate` inside the Signature element (document order). PDF: iText signing chain |
| `signingTime` | `Date` or null | yes | CMS `signingTime` attr; XAdES `SigningTime` parsed with `yyyy-MM-dd'T'HH:mm:ss` in the **local time zone, ignoring any offset/`Z`** (GOTCHA); PDF `/M` / signer date |
| `signAlgorithm` | String | yes | CMS/CAdES: `<digest>with<enc>` where digest ∈ `SHA1/SHA256/SHA384/SHA512` (else the OID string) and enc ∈ `RSA/DSA/ECDSA` (else OID); XML: the `SignatureMethod` **URI**; PDF: `pkcs7.getDigestAlgorithm()` (iText name, e.g. `SHA256withRSA`) |
| `pkcs1` | bytes | yes | raw signature value (CMS `encryptedDigest`, XML `SignatureValue` Base64-decoded, PDF PKCS#1) |
| `signFormat` | String | **never set** by shipped signers | — |
| `timestampingTime` | `Date[]` | **never set** by shipped signers | `isTimeStamped()` = non-empty and `[0] != null` |

`toString()` (what the UI tree shows): `getCN(certs[0])`, then ` (TimeStamp: <ts0>)` if timestamped, else ` (<signingTime>)` if present; dates formatted with Java `DateFormat.getDateTimeInstance(DEFAULT, SHORT)` in the default locale (e.g. es_ES on recent JDKs: `16 oct 2026, 13:17`; JDK 8: `16-oct-2026 13:17`) — locale/JDK-dependent; pick one and document it.

With `asSimpleSignInfo=false` the payload is the signer CN (`String`) (PDF: `AOUtil.getCN(signingCertificate)`; CMS: CN looked up by serial number).

### 12.3 `AOSignInfo` and `AOTimestampInfo`

* `AOSignInfo(format)` (null → `Desconocido`): `format`, `variant` (e.g. `XAdES Enveloped`), `urlSignObject`, `urlSignedData`, `b64VerificationCode` — all optional except format.
* `AOTimestampInfo(issuerCert, date)`: `toString()` = `Sello de tiempo emitido por '<CN|DESCONOCIDO>' con fecha <Date.toString()>`. afirma-simple builds a separate timestamps tree (`CompleteSignInfo.getTimestampsTree()`: root `Datos`, one `AOSimpleSignInfo([issuer], date)` child per timestamp).

---

## 13. UI abstractions, keystore interfaces, preferences

### 13.1 `AOUIManager` / `AOUIFactory`

Static facade over a pluggable UI manager (`es.gob.afirma.ui.core.jse.JSEUIManager`, `AWTUIManager` on macOS; Android → `UnsupportedOperationException`; `setUIManager` overrides). Constants are the Swing `JOptionPane` values: `PLAIN_MESSAGE=-1, ERROR_MESSAGE=0, INFORMATION_MESSAGE=1, WARNING_MESSAGE=2, QUESTION_MESSAGE=3, YES_NO_OPTION=0, OK_CANCEL_OPTION=2, YES_OPTION=0, OK_OPTION=0, NO_OPTION=1`. Operations: `getPassword(text, parent)`, `getPassword(text, icon, charset, beep, parent)` (charset = allowed chars), `getDoublePassword(text, text2, icon, charset, beep, parent)` (new-password + confirm), `showConfirmDialog(parent, msg, title, optionType, msgType) -> int`, `showMessageDialog(…)`, `showErrorMessage([parent,] msg, title, type, Throwable)`, `showInputDialog(parent, msg, title, type, icon, values[], initial) -> Object`, `showCertificateSelectionDialog(parent, KeyStoreDialogManager) -> alias`, `getLoadFiles(title, currentDir, filename, extensions[], description, selectDirectory, multiSelect, icon, parent) -> File[]`, `getSaveDataToFile(data, title, currentDir, selectedFile, List<GenericFileFilter>[, defaultFilter], parent) -> File`. Cancelling dialogs throws `AOCancelledOperationException`. `GenericFileFilter { String[] extensions; description }` (equals by both).

### 13.2 Keystore interfaces (`es.gob.afirma.core.keystores`)

* `KeyStoreManager`: `deactivateEntry(certThumbprint)`, `isKeyEntry(alias)`, `getAliases()`, `getCertificate(alias)`, `getCertificateChain(alias)`, `getKeyEntry(alias) -> PrivateKeyEntry`, `refresh()`, `setEntryPasswordCallBack(pwc)`, `setParentComponent(parent)`.
* `NameCertificateBean { alias, name (display), certificateChain }`; `getCertificate()` = chain[0] or null; `toString()` = name.
* `CertificateContext { KeyStoreManager ksm; String alias }`.
* `KeyStoreDialogManager` (ids §1.6): `refresh`, `getNameCertificates`, `setKeyStoreManager`, `changeKeyStoreManager(id, parent)`, `changeKeyStoreManagerToPKCS11(parent, name, libPath)`, `getAvailablesKeyStores()`, `getKeyEntry(alias)`, `show() -> alias`, `getSelectedAlias`, `getSelectedCertificateContext`, `allowOpenExternalStores(bool)`, `isExternalStoresOpeningAllowed`, `getKeyStoreName`, `getLibName`.
* `KeyUsage` §8.6. Implementations: keystores spec.

### 13.3 `afirma-core-prefs` — `KeyStorePreferencesManager` (registered PKCS#11 smart cards)

Java `java.util.prefs` nodes:
* user: `/es/gob/afirma/core/keystores`; system: `/es/gob/afirma/core/keystores` in the system root, or — if the user node `/es/gob/afirma/core/systemkeystores` exists **and** system pref `/es/gob/afirma/standalone/ui/internalpreferences` key `allowUpdateConfig` is true — that user node is used as "system" preferences.
* Each card = child node named `1`, `2`, … (first free integer) containing a single key `<cardName>` = `<PKCS#11 library path>`.
* `getUserSmartCardsRegistered()` / `getSystemSmartCardsRegistered()` → map name→lib (first key of each child node). `getAllSmartCardsMap()` = user ∪ system (system wins on same name).
* `putUserSmartCardsMap(map)`: skip entries whose lib is already registered (any scope); rename on clash `name-1`, `name-2`…; add.
* `putSystemSmartCardsMap(map)`: (creates system node; if not writable, falls back to the user node `/es/gob/afirma/core/systemkeystores`) remove all existing system cards, then add with name de-duplication.
* `deleteSmartCardRec(name)` (user only), `clearKeyStorePrefs()` (removes keys of the user node — not child nodes), `removeSystemPrefs()` (removes system node and empty parents), `lastSelectedKeystore` / `lastSelectedKeystoreLib` (in-memory only).
* Storage backends (interop with an existing installation): Linux `~/.java/.userPrefs/es/gob/afirma/core/keystores/<n>/prefs.xml` and `/etc/.java/.systemPrefs/…`; Windows registry `HKCU\Software\JavaSoft\Prefs\es\gob\afirma\core\keystores\<n>` (Java escapes uppercase letters in names/keys with `/`, e.g. `/D/N/Ie`) and `HKLM\Software\JavaSoft\Prefs\…`; macOS `~/Library/Preferences/com.apple.java.util.prefs.plist` (and `/Library/Preferences/…`). If parity with Java-written data is required, the Rust reader must implement these encodings.

---

## 14. ASiC-S helpers (`ASiCUtil`)

* `createSContainer(signature, data, signatureFilename=null→META-INF/signature.p7s, dataFilename=null→getASiCSDefaultDataFilename(data))`: ZIP with archive comment `mimetype=application/vnd.etsi.asic-s+zip`; entries in order: `mimetype` (content `application/vnd.etsi.asic-s+zip`, **DEFLATED** — Java default — not STORED as ETSI requires; GOTCHA), the data entry, the signature entry. Empty signature/data → IAE.
* `getASiCSBinarySignature(asic)` / `getASiCSXMLSignature(asic)`: content of entry `META-INF/signature.p7s` / `META-INF/signatures.xml` (exact name); size ≥ 1 GB → IOException; missing → `IOException("Los datos proporcionados no son una firma ASiC-S conteniendo la entrada …")`.
* `getASiCSData(asic) -> Map<baseName, bytes>`: every entry that `isDataEntry` (not `mimetype`, not the two signature names — note: directories and other `META-INF/*` files **are** returned), keyed by file base name; none → IOException.
* `getASiCSDataFilename(asic)`: first data entry's full name.

---

## 15. `es.gob.afirma.core.misc.protocol` (summary only)

Parses `afirma://<op>?…` invocation URIs into `UrlParameters*` objects (`ToSign`, `ToSignAndSave`, `ToSave`, `ToLoad`, `ToSelectCert`, `ForBatch`), with `ProtocolVersion` (`major[.minor]`; `isCompatibleWith` = same major; `hasSupportTo(v)` = major greater, or equal with minor ≥). Common parameter names: `op`, `properties` (Base64-URL extraParams, §3.5), `dat`, `gzip`, `rtservlet`, `stservlet`, `key`, `cipher`, `fileid`, `keystore`/`ksb64`, `aw`, `mcv`, `appname`, `servicetimeout`. `UrlParametersToSign/SignAndSave.expandExtraParams()` calls `ExtraParamsProcessor.expandProperties(extraParams, data, signatureFormat)`. Errors are `ParameterException`s carrying `ErrorCode.Request.*` codes (6xxxxx). Fully specified in the protocol spec.

---

## 16. Parity checklist

| Feature | Java class(es) | Notes for the Rust port |
|---|---|---|
| Format/algorithm/mode constants | `AOSignConstants`, `CounterSignTarget` | Exact strings §1; format lookup case-insensitive |
| Digest name normalisation | `AOSignConstants.getDigestAlgorithmName` | Returns `SHA1` (no hyphen) but `SHA-256/384/512`; `xmldsig-more#sha384` bug |
| Signature algorithm composition | `AOSignConstants.composeSignatureAlgorithmName` | key types `RSA`/`DSA`/`EC*` |
| ECDSA DER ↔ r‖s | `Pkcs1Utils` | `k = max(len r, len s)` |
| Signer traits | `AOSigner`, `AOCoSigner`, `AOCounterSigner`, `AOSimpleSigner`, `AOTriphaseSigner`, `OptionalDataInterface`, `AOConfigurableContext`, `SignEnhancer` | `isSign` never throws on garbage; null extraParams = empty |
| Raw PKCS#1 signer | `AOPkcs1Signer` | self-verification with cert[0]; JMulticard error mapping |
| PKCS#1 triphase | `AOPkcs1TriPhaseSigner`, `TriphaseData`, `TriphaseDataSigner`, `TriphaseUtil` | XML not escaped; URL-safe Base64 with padding; `OK NEWID=` |
| Signer registry & detection | `AOSignerFactory` | 29 rows, detection order §4.3; `getSignFormat(AOPDFSigner)` = `Adobe PDF`; CAdES-ASiC-S detection bug |
| Format auto-selection | afirma-simple `SignPanel`, `ProtocolInvocationLauncherUtil.identifyFormatFromData`, `DataAnalizerUtil` | defaults PDF→PAdES, FacturaE→FacturaE, OOXML/ODF/binary→CAdES, XML→XAdES |
| extraParams model | `java.util.Properties`, `AOUtil.base642Properties/properties2Base64`, `ExtraParamsProcessor.convertToProperties` | implement Java .properties load/store faithfully |
| Policy expansion | `ExtraParamsProcessor`, `AdESPolicyPropertiesManager`, `policy.properties` | only `FirmaAGE`, `FirmaAGE18`; override semantics; 1 MiB implicit rule; NPE on null format |
| AdES policy object | `AdESPolicy` | downloads policy when hash absent/"0"; hash algorithm normalised |
| Binary values in extraParams | `ExtraParamsProcessor.loadByteArrayFromExtraParams` | path vs Base64 heuristic (<255 chars & not Base64) only when not secure mode |
| AUTO-format PDF tweak | `ExtraParamsProcessor.configAutoFormat` → `AOPDFSigner.configureRespectfulProperties` | copies existing subfilter |
| MIME detection | `MimeHelper` (+JMimeMagic), `OfficeAnalizer`, `AOFileUtils.isXML` | replace JMimeMagic with own magic table; DOCTYPE ⇒ not XML; `application/octect-stream` typo |
| OID ↔ MIME | `MimeHelper.transformMimeTypeToOid/OidToMimeType`, `mimetypes_oids.properties` | 16-entry table; `data` pseudo-MIME |
| Base64 | `misc.Base64` | strict alphabet per mode; padding stop; trailing partial quartet dropped; `isBase64` rules |
| DN/CN helpers | `AOUtil.getCN/getRDNvalueFromLdapName/getOUS/isPseudonymCert` | Java `X500Principal.toString()` rendering needed |
| URI/file loading | `AOUtil.createURI/loadFile`, `DataDownloader` | escaping table; resolution order |
| Platform | `Platform` | OS/arch enums, lib dirs |
| Logging helpers | `LoggerUtil`, `LogManager` | `USERHOME` masking; 200-char trimming; `~/.afirma/<APP>.afirma.log.xml` |
| Secure XML | `SecureXmlBuilder`, `SecureXmlTransformer` | reject DOCTYPE; no external entities |
| HTTP client | `UrlHttpManager(Impl)`, `UrlHttpManagerFactory`, `ConnectionConfig`, `SSLConfig`, `HttpError`, `URLName` | POST query→body (form-urlencoded); loopback ⇒ no proxy; 4xx/5xx ⇒ HttpError; global cookie jar; shared read timeout; restricted headers dropped |
| TLS trust | `SslSecurityManager`, `MultiX509TrustManager`, `TrustStoreManager` | system roots ∪ `~/.afirma/TrustedCertsKeystore.jks`; `disableSslChecks`/`secureDomainsList` |
| Interactive SSL import | `SSLErrorProcessor` | only on handshake errors; hostname check vs SAN/CN; imports issuers; retry once; static cancel memory |
| Error codes | `ErrorCode` + module holders | 6-digit codes, equality by code; complete table §10.6 |
| Exceptions | `AOException`, `AORuntimeException`, `RuntimeConfigNeededException`… | default codes §10.2; confirmation/password retry loop |
| Protocol error surfacing | afirma-simple `ProtocolInvocationLauncherErrorManager` | `err-00:=AF<code> - <desc>` (≥4.1) vs `SAF_xx` legacy |
| Validation API | `SignValidity`, `SignValider`, `SignValiderFactory` | first element = verdict; KO priority; LTS swap |
| CMS validation | `ValidateBinarySignature` | integrity + validity dates only |
| PDF validation | `ValidatePdfSignature`, `DataAnalizerUtil.checkPdfShadowAttack/checkPDFForm` | form-change & shadow-attack checks; certified PDFs |
| XML validation | `ValidateXMLSignature` | JSR-105 semantics; no KO reordering |
| Profile detection | `SignatureFormatDetectorPadesCades`, `SignatureFormatDetectorXades`, `ISignatureFormatDetector` | timestamped ⇒ `SIGN_PROFILE_NOT_CHECKED` |
| Signers tree | `AOTreeNode`, `AOTreeModel`, `AOTreeUtil`, `AOSimpleSignInfo`, `AOSignInfo`, `AOTimestampInfo` | root `Datos`; countersigns as children; node text `CN (date)` |
| ASiC-S container | `ASiCUtil` | entry names; DEFLATED mimetype; archive comment |
| UI facade | `AOUIManager`, `AOUIFactory`, `GenericFileFilter`, `CoreMessages`, `LanguageManager` | JOptionPane constant values; `!key!` for missing messages |
| Keystore interfaces | `KeyStoreManager`, `KeyStoreDialogManager`, `NameCertificateBean`, `CertificateContext`, `KeyUsage` | ids 1–5 |
| Smart-card registry prefs | `afirma-core-prefs/KeyStorePreferencesManager` | Java Preferences node layout & backends |
| Ciphers/envelopers | `AOCipher`, `AOCipherConfig`, `CipherConstants`, `AOEnveloper` | interfaces/enums only |
| Misc | `BoundedBufferedReader`, `AOFileUtils.pathLengthShortener`, `AOUtil.hexify/split` | exact algorithms §7–§8 |

---

## 17. Notable gotchas (summary)

1. `CAdES-ASiC-S` is never detected by `AOSignerFactory.getSigner(bytes)` (recursive `isSign` bug).
2. `getSignFormat(AOPDFSigner)` returns `Adobe PDF`, not `PAdES` (affects AUTO co-sign format names).
3. Defaults for OOXML and ODF files are **CAdES**, not OOXML/ODF; in the protocol `auto` mode they are CAdES too.
4. `expPolicy` accepts only `FirmaAGE` and `FirmaAGE18` (not `FirmaAGE19`); PAdES only with `FirmaAGE`; expanded values override user values; null format ⇒ NPE when `expPolicy` is present.
5. `getDigestAlgorithmName` returns `SHA1` (no hyphen) and mangles `…xmldsig-more#sha384` into `more#sha384`.
6. `ExtraParamsProcessor.convertToProperties` mixes platform charset and ISO-8859-1; `base642Properties` uses UTF-8.
7. `Base64.isBase64` accepts `~`, `-`, `_`, tabs, and rejects `"…==\n"`; the decoders silently drop trailing partial quartets.
8. HTTP: POST bodies are the URL query (second `?` truncates); JDK drops `Host`/`Origin`/`Connection`/`Content-Length` set by code; no timeouts by default; the read timeout lives on a shared singleton; a global accept-all cookie jar is installed.
9. A host in `secureDomainsList` disables TLS checks even when an explicit `SSLConfig` is provided; entries are not trimmed and are case-sensitive.
10. `SSLErrorProcessor` imports only issuer certs (not the leaf) when the chain has >1 cert, and remembers a cancel for the whole process.
11. Duplicate numeric error codes across modules (200118, 200410, 213004, 501001, 600116) are equal at runtime; `UNKNOWN_SIGNING_ERROR` maps to `SAF_03` (second put wins).
12. Protocol dialog text lookup for 1xxxxx/2xxxxx codes skips the category fallback (missing `else`).
13. `AOSimpleSignInfo.signFormat` and `timestampingTime` are never filled; XAdES signing time is parsed ignoring the time-zone.
14. Validation never checks trust chains or revocation; any timestamped/long-term signature yields "Validación incompleta" (`SIGN_PROFILE_NOT_CHECKED`); PDF `validate(sign, Properties)` does not check certificate dates unless `checkCertificates=true` is passed.
15. `MimeHelper.isZipData()` only trusts JMimeMagic (byte check is dead code); `OfficeAnalizer` falls back to the misspelt `application/octect-stream`.
16. XML with a DOCTYPE declaration is treated as non-XML (binary → CAdES).
17. ASiC-S `mimetype` entry is DEFLATED (non-conformant), and the container carries a ZIP comment `mimetype=…`.
18. `AdESPolicy` silently downloads the policy document (no proxy/timeout handling) when no hash is given.
19. extraParams can carry non-string Java objects (`confirmDifferentProfile` = `Boolean.TRUE`), invisible to `getProperty`, impossible to send from the web, and fatal to `expandProperties`.
