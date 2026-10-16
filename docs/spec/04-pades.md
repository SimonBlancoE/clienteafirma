# 04 — PDF / PAdES signing (`afirma-crypto-pdf`, `afirma-crypto-pdf-common`, `afirma-crypto-padestri-client`, PAdES validation, PDF UI)

This document specifies, precisely enough for a Rust re-implementation without reading the Java code, everything
AutoFirma does with PDF signatures: the signer API, every extra parameter, the exact PDF objects written, the CMS
embedded in `/Contents`, timestamps, the visible-signature appearance, multi-signature/certified/encrypted handling,
the "PDF Shadow Attack" checks, PAdES validation, the three-phase (server assisted) split, and the desktop UI that
builds the visible-signature parameters.

## 0. Scope, sources, conventions

### 0.1 Sources

| Module / package | Classes |
|---|---|
| `afirma-crypto-pdf` `es.gob.afirma.signers.pades` | `AOPDFSigner`, `PAdESTriPhaseSigner`, `PdfSessionManager`, `PdfUtil`, `PdfVisibleAreasUtils`, `PdfPreProcessor`, `PdfTimestamper`, `PdfTextMask`, `XmpHelper`, `PdfSignResult`, `PdfTriPhaseSession`, `InvalidPdfException`, `InvalidSignaturePositionException`, `IncorrectPageException`, `InvalidITextException`; resources `fonts/{courier,helvetica,times}.ttf` (GNU FreeFont), `enhancer.properties` |
| `afirma-crypto-pdf-common` `es.gob.afirma.signers.pades.common` | `PdfExtraParams`, `PdfErrorCode`, `BadPdfPasswordException`, `PdfIsPasswordProtectedException`, `PdfIsCertifiedException`, `PdfHasUnregisteredSignaturesException`, `PdfFormModifiedException`, `SuspectedPSAException` |
| `afirma-crypto-padestri-client` | `AOPDFTriPhaseSigner`, `PDFTriPhaseSignerUtil` |
| `afirma-server-triphase-signer-core` / `-signer` | `PAdESTriPhasePreProcessor`, `SignatureService`, `TriPhaseHelper`, `ConfigManager` (PAdES parts) |
| `afirma-crypto-cades`, `afirma-crypto-core-pkcs7`, `afirma-crypto-core-pkcs7-tsp` | `CAdESTriPhaseSigner`, `CAdESUtils.generateSignedAttributes`, `CAdESParameters`, `SigUtils`, `CMSTimestamper`, `TsaParams` (only the parts PAdES uses) |
| `afirma-crypto-validation` `es.gob.afirma.signvalidation` | `ValidatePdfSignature`, `DataAnalizerUtil` (PSA/form checks), `SignatureFormatDetectorPadesCades` (PAdES profile detection), `SignValider`, `SignValidity` |
| `afirma-simple` `es.gob.afirma.standalone.ui.pdf` (+ `ui.SignPanel`, `ui.SignPanelSignTask`, `ui.ExtraParamsHelper`, `ui.preferences.PreferencesPanelPades`, `protocol.ProtocolInvocationLauncherSign*`) | Visible signature / stamp dialogs, preferences, retry flows |
| `afirma-ui-utils` | `ImageUtils.normalizeImageToPdf` (image → JPEG) |
| **Patched iText 2.1.7** (`es.gob.afirma.lib:afirma-lib-itext:1.7`, package `com.aowagie.text`) | Not in this repo. Its sources jar is on Maven Central; it was used to verify every PDF-level statement here (`PdfStamper`, `PdfStamperImp`, `PdfSignatureAppearance`, `AcroFields`, `PdfPKCS7`, `PdfWriter`, `PdfDate`, `PdfEncryption`, `PdfChunk`, `ColumnText`). |

**Empirical verification.** All PDF-structure statements in §5–§8 were cross-checked by compiling the Java modules
listed above against `afirma-lib-itext-1.7.jar` + SpongyCastle 1.58.0.0 and signing the test PDFs in
`afirma-crypto-pdf/src/test/resources` (default, visible, co-sign, multi-page, certified, rotated, rubric,
existing field, encrypted, `pdfVersion`, `compressPdf`, `signReservedSize`, TSA). Literal outputs quoted below
(marked *observed*) come from those runs.

### 0.2 Conventions

- `code` = exact literal. Extra parameters ("extraParams") are a Java `Properties` (string → string). Booleans are
  parsed with Java `Boolean.parseBoolean` (**only** the case-insensitive literal `true` is true; anything else,
  including `1`/`yes`, is false) unless stated otherwise.
- "Unset" = key absent. Several behaviours differ between *unset* and *set to `false`* — they are called out.
- **Quirk:** / **Gotcha:** / **Bug:** mark legacy behaviour that a reimplementation must consciously replicate or fix.
  For a 1:1 port, replicate unless the item says "fix recommended".
- "iText" always means the patched iText 2.1.7 (`com.aowagie.text`).
- PDF coordinates are user-space points, origin bottom-left, as displayed (i.e. *after* page `/Rotate`, see §8.9).
- Cross references: `07-core.md` (AOUtil, Base64, `TriphaseData`, `expPolicy`, algorithm names, Properties text
  format), `06-app-ui-cli-installer.md` §3/§4 (generic UI and preferences storage), the CAdES spec (CAdES signed
  attributes in general).

---

## 1. Formats and signer API

### 1.1 Format names → signer class

From `AOSignerFactory` (`07-core.md` §4):

| Format name (exact) | Class | Used for auto-detection (`isSign`) |
|---|---|---|
| `Adobe PDF` (`SIGN_FORMAT_PDF`) | `es.gob.afirma.signers.pades.AOPDFSigner` | no |
| `PAdES` (`SIGN_FORMAT_PADES`) | `AOPDFSigner` | **yes** |
| `Adobe PDF TriPhase` (`SIGN_FORMAT_PDF_TRI`) | `es.gob.afirma.signers.padestri.client.AOPDFTriPhaseSigner` | no |
| `PAdEStri` (`SIGN_FORMAT_PADES_TRI`) | `AOPDFTriPhaseSigner` | no |

`Adobe PDF` and `PAdES` are **the same implementation**; the name only matters for detection order and for the
`expPolicy` normalisation (all four names normalise to `PAdES`, §3.11). There is no separate "PAdES-BES" or
"PAdES-Basic" format: the variant is chosen with `signatureSubFilter` (§3.1). The protocol launcher additionally
accepts the literals `ETSI.CAdES.detached` and `adbe.pkcs7.detached` as *format* names when deciding whether to show
the visible-signature dialog (§12.6).

Constants (`AOSignConstants`): `PADES_SUBFILTER_BASIC = "adbe.pkcs7.detached"`, `PADES_SUBFILTER_BES =
"ETSI.CAdES.detached"`, `SIGN_PROFILE_ADVANCED = "advanced"` (default), `SIGN_PROFILE_BASELINE = "baseline"`,
`DEFAULT_SIGN_ALGO = "SHA512withRSA"`.

### 1.2 `AOPDFSigner` (implements `AOSigner`, `AOConfigurableContext`)

| Method | Behaviour |
|---|---|
| `sign(data, algorithm, key, certChain, extraParams) -> byte[]` | Full pipeline §2. `algorithm == null` → `SHA512withRSA`. `extraParams` is **cloned** first (caller's object is not modified). Returns the complete signed PDF. |
| `cosign(data, sign, algorithm, key, chain, xp)` | Ignores `data`; returns `sign(sign, algorithm, key, chain, xp)`. A PDF "co-signature" is simply another serial signature in a new revision. |
| `cosign(sign, algorithm, key, chain, xp)` | `sign(sign, …)`. |
| `countersign(...)` | Always throws `UnsupportedOperationException("No es posible realizar contrafirmas de ficheros PDF")`. |
| `getSignersStructure(sign, asSimpleSignInfo)` / `(sign, params, asSimpleSignInfo)` | §1.3. Never throws: errors → tree with only the root. |
| `isSign(data)` / `isSign(data, params)` | §1.4 |
| `isValidDataFile(data)` | `data == null` → false (warn); else `isPdfFile(data)` (§1.4). |
| `getData(sign[, params])` | If `!isSign(sign[, params])` → `AOInvalidSignatureFormatException("El documento introducido no contiene una firma valida")`; else returns **the same bytes unchanged** (TODO in Java: never extracts the unsigned revision). |
| `getSignInfo(data[, params])` | `data == null` → `IllegalArgumentException`; `!isSign` → `AOInvalidSignatureFormatException`; else `new AOSignInfo("Adobe PDF")` (no further analysis). |
| `getSignedName(originalName, inText)` | `null` → `"signed.pdf"`; if name ends with `.pdf` (case-insensitive) → `base + inText + ".pdf"`; else `originalName + inText + ".pdf"`; `inText == null` → `""`. |
| static `getSignedName(originalName)` | `null` → `"signed.pdf"`; ends with `.pdf` → `replace(".pdf", ".signed.pdf")` (**Quirk:** `String.replace` replaces *every* occurrence); ends with `.PDF` → `replace(".PDF", ".signed.pdf")`; else `+ ".signed.pdf"`. |
| static `configureRespectfulProperties(data, config)` | If `config` lacks `signatureSubFilter`: find the first `/Type /Sig` dictionary (scanning xref objects 0..n in order) whose `/SubFilter` is one of `/ETSI.RFC3161`, `/adbe.pkcs7.detached`, `/ETSI.CAdES.detached`, `/adbe.pkcs7.sha1`, and set `signatureSubFilter` to it without the leading `/`. Only used by the legacy MiniApplet "AUTO" format. **Bug:** may copy `ETSI.RFC3161` from a document timestamp, producing a signature with SubFilter `ETSI.RFC3161`. |
| `setSecureMode(bool)` / `isSecureMode()` | Default `true`. When `false`, `signatureRubricImage`, `image` and `attach` may be **file paths/URIs** (< 500 chars) instead of Base64 (§3.6). |
| static `getSignEnhancer()` / `getSignEnhancerConfig()` | Loaded once from classpath `/enhancer.properties`, key `enhancerClassFile` (commented out in the shipped file → enhancer is `null`). If configured, `enhancer.enhance(cms, config)` post-processes the CMS (§6.6). |

Static initialiser side effect: in JCA providers `SunEC`, `BC`, `SC` it registers aliases
`SHA{224,256,384,512}with1.2.840.10045.4.3.2 → SHA{…}withECDSA` (iText ECDSA naming workaround). Not needed in Rust.

`checkParams` (run at the start of `sign`, mutates the cloned params):

1. `algorithm.toUpperCase().startsWith("MD")` → `IllegalArgumentException("PAdES no permite huellas digitales MD2 o MD5 (Decision 130/2011 CE)")`.
2. `profile` equals (ignore case) `baseline`: warn if SHA-1 algorithm; if `signatureSubFilter` present → warn and **remove** it (baseline always uses `ETSI.CAdES.detached`).
3. `commitmentTypeIndications` present and profile ≠ baseline and no `policyIdentifier` → remove `commitmentTypeIndications` ("not allowed in PAdES-EPES" message — actually means BES).
4. `signReason` and `policyIdentifier` both present → **remove `signReason`**.
5. `signReason` and `commitmentTypeIndications` both present (after step 3/4) → remove `commitmentTypeIndications`.

### 1.3 `getSignersStructure(sign, params, asSimpleSignInfo)`

1. Root node `"Datos"`. If `!isPdfFile(sign)` → return root only.
2. Open with `PdfUtil.getPdfReader(sign, params, headless)` (passwords from `ownerPassword`/`userPassword`, §9.4). On
   `BadPdfPasswordException`, `PdfIsPasswordProtectedException` or any exception → root only (logged).
3. Signature names = `AcroFields.getSignatureNames()` (§9.1). For each name:
   - Skip if the signature dictionary `/SubFilter` is `/ETSI.RFC3161` or `/DocTimeStamp` (document timestamps;
     **Quirk:** `/DocTimeStamp` is really a `/Type` value, so that second test never matches).
   - `PdfPKCS7 = AcroFields.verifySignature(name)` (parses CMS, hashes byte range, takes `/M`, `/Name`, `/Reason`,
     `/Location`, `/ContactInfo`). Exceptions → skip (logged as corrupt).
   - `asSimpleSignInfo == false`: child node = `AOUtil.getCN(signingCertificate)` (String).
   - `true`: child node = `AOSimpleSignInfo(certChain = PdfPKCS7.getSignCertificateChain(), signingTime =
     PdfPKCS7.getSignDate()` (= `/M` decoded, or CMS signingTime if no `/M`), `pkcs1 = signature value bytes`,
     `signAlgorithm = PdfPKCS7.getDigestAlgorithm()` (e.g. `SHA256withRSA`)).
4. All signers hang directly from the root (flat list).

**Order:** iteration order of iText's `getSignatureNames()`, which returns `new ArrayList(HashMap.keySet())` — i.e.
Java `HashMap` order of the field names. For iText-generated names `Signature1…Signature10` this happens to be
newest-first (`Signature10, Signature9, …, Signature1`); for other names it is arbitrary. **Recommended for Rust:**
order by revision descending (newest first), which reproduces Java for the common case. `ValidatePdfSignature`
depends on "index 0 = newest" (§10).

### 1.4 `isSign` / `isPdfFile`

`isPdfFile(data)`: `data != null`, `length >= 70` (`PDF_MIN_FILE_SIZE`), first 5 bytes == `%PDF-`, and iText
`new PdfReader(data)` succeeds. A `BadPasswordException` (encrypted, no password) counts as **valid PDF** (true).

`isSign(data, params)`:
1. `data == null` → false. `!isPdfFile` → false.
2. If `getSignersStructure(data, params, false)` has ≥ 1 child → true (document timestamps are excluded, so a PDF
   with only a `/DocTimeStamp` is *not* a signature).
3. Else, using **`System.getProperties()`** (not `params`!) as extraParams: if the PDF has unregistered signatures
   (§9.2) **and** system property `allowCosigningUnregisteredSignatures` equals (ignore case) `true` → true.
4. Else false.

### 1.5 `AOPDFTriPhaseSigner`

Client side of the three-phase protocol (§11). `sign(data, …)`: `data` is the **document identifier** (not the PDF),
required extraParam `serverUrl`. `cosign` = `sign(sign, …)`. `countersign` → `UnsupportedOperationException("No se
soportan contrafirmas en PAdES")`. `getSignersStructure` → `UnsupportedOperationException`. `isSign` → always
`false`. `isValidDataFile` → `%PDF-` header and length ≥ 70 only. `getSignInfo` → requires `isSign` (always false →
always throws). `getSignedName` as in §1.2.

---

## 2. Signing pipeline (`AOPDFSigner.sign`) — exact order

```
sign(inPDF, algo, key, chain, xParams):
  algo        = algo ?: "SHA512withRSA"
  xp          = clone(xParams ?: {})
  checkParams(algo, xp)                                   # §1.2
  chain'      = includeOnlySignningCertificate=="true" ? [chain[0]] : chain
  signTime    = parseSignTime(xp.signTime)                # §3.12; default now()
  data        = inPDF
  if PdfTimestamper.isAvailable():                        # TSP classes on classpath (always in AutoFirma)
      data = PdfTimestamper.timestampPdf(data, xp, signTime)   # document timestamp, only tsType 2|3 (§7.3)
  pre  = PAdESTriPhaseSigner.preSign(algo, data, chain', signTime, xp, secureMode)
           # = PdfSessionManager.getSessionData(...)  -> builds the whole new PDF revision with a
           #   placeholder /Contents, returns (appearance, output buffer, fileID)
           # + hash of the ByteRange + CAdES signed attributes (DER)        (§6)
  pkcs1 = AOPkcs1Signer.sign(pre.signedAttributesDER, algo, key, chain', xp)   # PKCS#1 v1.5 / ECDSA
  return PAdESTriPhaseSigner.postSign(algo, data, chain', pkcs1, pre, enhancer, enhancerConfig, secureMode)
           # builds the CMS (+ optional signature timestamp, enhancer),
           # calls getSessionData(...) AGAIN with the same inputs and signTime,
           # writes the CMS into /Contents, closes the PDF,
           # replaces (ISO-8859-1 string replace, all occurrences) the new random file ID
           # with the file ID produced during preSign.
```

**Gotcha (determinism):** the PDF is generated twice (pre and post) and the second generation must be
byte-identical to the first except for the random trailer `/ID` (which is then patched back). Everything else must
be a pure function of (input PDF, params, certificate chain, signTime). A Rust implementation may generate once and
patch `/Contents` in place (same final bytes), but the three-phase server *must* be deterministic (§11).

Errors in `timestampPdf` that are `IOException` are wrapped as `AOException("Error en la composicion del sello de
tiempo de la firma", INTERNAL_PADES_SIGNING_ERROR)`; `NoSuchAlgorithmException` in post-sign →
`AOException(UNSUPPORTED_SIGNATURE_ALGORITHM)`.

---

## 3. Extra parameters (complete reference)

Keys are case-sensitive. "Default" is the behaviour when unset.

### 3.1 Signature type / CMS content

| Key | Type / values | Default | Effect |
|---|---|---|---|
| `signatureSubFilter` | `adbe.pkcs7.detached` \| `ETSI.CAdES.detached` \| any name | **`ETSI.CAdES.detached`** (code default in `PdfSessionManager`; the Javadoc claiming `adbe.pkcs7.detached` is wrong — *observed*) | Written verbatim as `/SubFilter` (a PDF name; no validation). Empty string → default. **Forced to `ETSI.CAdES.detached`** (and the param overwritten) when `policyIdentifier` is set or `profile` equals (case-*sensitive* here) `baseline`. The embedded CMS is identical for both sub-filters (CAdES attributes are always used). |
| `profile` | `advanced` \| `baseline` | `advanced` | `baseline`: forces sub-filter (above), removes explicit `signatureSubFilter` (§1.2), allows commitment types without policy, claimed roles use `signer-attributes-v2`. |
| `includeOnlySignningCertificate` (sic, double n) | bool | false | Only `chain[0]` goes into the CMS `certificates`, into the triphase `cert` URL param, and into appearance/`/Name` processing. |
| `signingCertificateV2` | bool | see rule | If the signature algorithm is one of `SHA{256,384,512}with{RSA,ECDSA}` → always V2 (param ignored). Else if set → V2 iff `true`. Else V2 iff digest ≠ SHA1. |
| `doNotIncludePolicyOnSigningCertificate` | bool | false | `false` → the signing certificate's `certificatePolicies` (2.5.29.32) are copied into `SigningCertificate[V2].policies`. |
| `policyIdentifier` | OID or `urn:oid:` OID (case-insensitive prefix stripped) | none | Adds `id-aa-ets-sigPolicyId` (§6.3); forces `ETSI.CAdES.detached`; removes `signReason` (§1.2). |
| `policyIdentifierHash` | Base64 or `0` | none | Policy hash. Absent or `0` → the identifier is opened **as a URL** and its content hashed (fails with `IllegalArgumentException` if not a reachable URL — OIDs are not URLs). Must be valid Base64. |
| `policyIdentifierHashAlgorithm` | any name accepted by `getDigestAlgorithmName` (`SHA1`, `SHA-256`, `http://www.w3.org/2000/09/xmldsig#sha1`, …) | `SHA-512` when hash computed from URL; **mandatory** when a hash is given | `sigPolicyHash.hashAlgorithm`. |
| `policyQualifier` | URL | none | `SigPolicyQualifierInfo { id-spq-ets-uri (1.2.840.113549.1.9.16.5.1), IA5String(url) }`. Must parse as `java.net.URL`. |
| `expPolicy` | `FirmaAGE` \| `FirmaAGE18` | none | Pre-processing in callers (`ExtraParamsProcessor.expandProperties`, `07-core.md` §5): for PAdES only `FirmaAGE` is accepted (→ OID `2.16.724.1.3.1.1.2.1.9`, hash `G7roucf600+f03r/o0bAOQ6WAs0=` SHA1, qualifier `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf`, and `signatureSubFilter=ETSI.CAdES.detached`; an explicit different sub-filter → `SignaturePolicyIncompatibilityException`). `FirmaAGE18` with PAdES → `SignaturePolicyIncompatibilityException`. |
| `commitmentTypeIndications` | integer n ≥ 1 | none | Number of commitment types; entries read for i = 0..**n inclusive** (off-by-one: n+1 slots). Removed by §1.2 rules (needs policy or baseline; removed if `signReason` set). |
| `commitmentTypeIndication<i>Identifier` | `1`..`6` | — | 1=proofOfOrigin, 2=proofOfReceipt, 3=proofOfDelivery, 4=proofOfSender, 5=proofOfApproval, 6=proofOfCreation (OIDs `1.2.840.113549.1.9.16.6.1`..`.6`). Unknown → entry skipped. |
| `commitmentTypeIndication<i>CommitmentTypeQualifiers` | `oid1\|oid2\|…` (pipe-separated) | none | `commitmentTypeQualifier` = `SEQUENCE OF OBJECT IDENTIFIER` (non-standard encoding, replicate). |
| `signerClaimedRoles` | `role1\|role2\|…` (pipe-separated) | none | `signer-attributes` (`1.2.840.113549.1.9.16.2.18`, profile advanced) or `signer-attributes-v2` (`0.4.0.19122.1.1`, baseline): `SEQUENCE { [0] SEQUENCE OF Attribute{ id-at-role (2.5.4.72), SET{UTF8String role} } }`. Empty roles skipped. |
| `includeMimeTypeAttribute` / `mimeType` | bool / string | false | **Quirk:** honoured in PAdES: adds `id-aa-ets-mimeType` (`0.4.0.1733.2.1`, UTF8String) = `mimeType` or `application/octet-stream`. Don't set it. |
| `precalculatedHashAlgorithm` | — | — | **Gotcha:** if set, the *messageDigest* is computed with that algorithm instead of the signature algorithm's digest. Never set it for PAdES. |
| Ignored for PAdES | `signingTime`/`includeSigningTimeAttribute`, `contentTypeOid`, `contentDescription`, `includeContentHintAttribute`, `mode`, `signatureProductionPostalCode`, `signatureProductionCountry` | | PAdES forces: no signingTime, no content-hints, no signer-location (`PAdESTriPhaseSigner.preSign`). `signatureProductionCity` is used only for the PDF `/Location`. |

### 3.2 PDF signature dictionary metadata

| Key | Type | Default | Effect |
|---|---|---|---|
| `signReason` | string | none | `/Reason` (PDF text string, PDFDocEncoding or UTF-16BE with BOM). Also `$$REASON$$` and the default text line `Motivo:`. Removed when a policy is set. |
| `signatureProductionCity` | string | none | `/Location`; `$$LOCATION$$`; default text line `Lugar de firma:`. |
| `signerContact` | string | none | `/ContactInfo`; `$$CONTACT$$`. |
| `doNotUseCertChainOnPostSign` | bool | false | No `/Name` in the signature dictionary and no certificate passed to the appearance (`setCrypto(null, null, …)`). Visible text tokens are still resolved from the chain. |
| `signTime` | `yyyy:MM:dd:HH:mm:ss` (local time zone) | now | Signing time used for `/M`, Info `/ModDate`, XMP dates, `$$SIGNDATE$$`, TSA nonce, determinism. Parse failure → now (logged severe). |

### 3.3 Visible signature: area, page, field

| Key | Type / values | Default | Effect |
|---|---|---|---|
| `signaturePositionOnPageLowerLeftX` / `…LowerLeftY` / `…UpperRightX` / `…UpperRightY` | **integers** (`Integer.parseInt(trim)`; decimals are invalid) | none | All four must be present and parse, else no area (invalid → logged, treated as absent). Rectangle in points on the displayed page. Signature is *visible* iff a field is named (`signatureField`) or this rectangle has non-zero width and height (`isVisibleSignature`). |
| `signaturePages` | page list (below) | — | **Takes precedence** over `signaturePage` when present (even if empty). |
| `signaturePage` | page list | last page | Compat alias with identical syntax. |
| `signatureField` | field name | none | Sign an **existing** signature field (must exist and be `/FT /Sig`, else `IllegalArgumentException("The field X does not exist.")` / `"... is not a signature field."`). Position/page/rotation/rubric params are then ignored for placement (§8.10). The appearance text is still generated. |
| `signatureRotation` | integer degrees (normally `0`/`90`/`180`/`270`) | `0` | Rotates the *content* (text + rubric) inside the unrotated field rectangle, counter-clockwise (§8.7). Non-integer → `NumberFormatException` (not caught → signing fails). |

**Page list syntax** (`PdfUtil.getPages`): value split on `,`.
- If the **first** element (trimmed) equals (ignore case) `append` → a new blank page is appended (size and rotation
  of page 1, `stp.insertPage(N+1, pageSizeWithRotation(1))`) and the signature goes there (only when no
  `signatureField`). The rest of the list is ignored. *Observed* new page object (last kid of the last page's
  `/Parent`): `<</Type/Page/Resources<</ProcSet[/PDF/Text/ImageB/ImageC/ImageI]>>/Rotate 0/MediaBox[0 0 595 842]
  /Parent n 0 R/Annots[w 0 R]>>` (no `/Contents`). `1,append` adds **no** page (*observed*).
- Else if the first element equals (ignore case) `all` → every page 1..N.
- Else each element: spaces removed; if it parses as an integer → `normalizePage`; otherwise treated as a range
  `a-b` (if it starts with `-`, the separator is the next `-` after index 0, so `-3--1` = from −3 to −1). Invalid
  element → `IncorrectPageException` caught → logged and ignored. Range with end < start → ignored.
- `normalizePage(p)`: `p < 0` → `p + N + 1`; then `p <= 0` → 1; `p > N` → N. **Quirk:** `0` therefore means page 1
  (not "new page"), `999` means last page, `-999` means page 1.
- Duplicates are skipped, list sorted ascending, empty result → `[N]`.
- After that, `correctPositionSignature`: pages whose (rotated) width ≤ LLX or height ≤ LLY are removed; if none
  remain → `InvalidSignaturePositionException("La posicion proporcionada no se encuentra en el rango de ninguna de las
  paginas a estampar del documento")` (code `610301`). Then the rectangle is clipped to the **first** remaining
  page: `top = min(top, page.top)`, `right = min(right, page.right)` (no clipping of left/bottom, no clipping
  against other pages).
- The first page of the list is the "main" page (`setVisibleSignature(rect, pages[0])`); an invalid page number there
  (`InvalidPageNumberException`) is caught: the signature silently becomes invisible.

### 3.4 Visible signature: appearance

| Key | Type / values | Default | Effect |
|---|---|---|---|
| `layer2Text` | template string (tokens §8.2) | default text §8.3 (only if no `signatureRubricImage`) | Text of layer n2. Empty string → no text. |
| `layer2FontFamily` | `0` Courier, `1` Helvetica, `2` Times-Roman, `3` Symbol, `4` ZapfDingbats | `0` | **Quirk:** 3 and 4 fall back to **Courier** glyphs (only 0/1/2 have a base font mapping). Invalid integer → default. |
| `layer2FontSize` | integer | `12` | Font size (points) and leading. Invalid → 12. |
| `layer2FontStyle` | bit mask: `0` normal, `1` bold, `2` italic, `3` bold+italic, `4` underline, `8` strikethrough (OR-able) | `0` | Bold/italic are **simulated** (fill+stroke, skew), §8.5. |
| `layer2FontColor` | `black`, `white`, `lightGray`, `gray`, `darkGray`, `red`, `pink` | `black` | RGB table §8.5; unknown → black. **Bug:** the value is lower-cased before the lookup but the table keys `lightGray`/`darkGray` are camel-case, so **`lightGray` and `darkGray` always render black** (*observed*); the other names are effectively case-insensitive. |
| `layer4Text` | template string | none | Text of layer n4. Only rendered when `includeQuestionMark=true` (Acrobat 6 layers off) and then into a zero-height box (§5.6) — effectively invisible. |
| `includeQuestionMark` | bool | false | `true` → legacy 5-layer appearance (n0..n4, question-mark glyph in n1/n3); also sets layer4 text to the question-mark *operator string* (**Bug**, overridden by `layer4Text` if present). |
| `signatureRubricImage` | Base64 image (secure mode) | none | Handwritten-signature image drawn in n2 (§8.6). Any format readable by Java ImageIO is accepted if `afirma-ui-utils` is on the classpath (it is converted to JPEG); otherwise must be JPEG. Decoding error → `IOException("Se ha proporcionado una imagen de rubrica que no esta codificada en Base64")`, non-JPEG → `IOException("... no esta codificada en JPEG")`. Presence suppresses the default text. |
| `obfuscateCertText` | bool | **true**, except `false` when the signing cert is a pseudonym certificate (subject has `2.5.4.65`) | Masks identifiers in `$$SUBJECTCN$$` and `$$SUBJECTDN$$` (and in tokens derived from the DN) (§8.4). Explicit value always wins. |
| `obfuscationMask` | `char;minDigits;positions;shift` e.g. `*;3;false,false,false,true,true,true,true;true` | default mask (same as example) | §8.4. Malformed → default mask (logged). |

### 3.5 Certification, revisions, version, compression, size

| Key | Type / values | Default | Effect |
|---|---|---|---|
| `certificationLevel` | `0` not certified, `1` no changes, `2` form filling, `3` form filling + annotations | not certified | `>0` → DocMDP (§5.7). Invalid → ignored (logged). Value `0` → no DocMDP (`certificationLevel > 0` test). AutoFirma does **not** check that the document is unsigned. |
| `allowSigningCertifiedPdfs` | `true` / anything else / unset | unset | Input PDF with DocMDP P=1: unset → `PdfIsCertifiedException` (confirmable, §9.3); `true` → sign anyway; any other value → `PdfIsCertifiedException` with `denied=true`. P=2/3 never blocks. |
| `allowCosigningUnregisteredSignatures` | `true` / anything else / unset | unset | Input has "unregistered" signatures (§9.2): unset → `PdfHasUnregisteredSignaturesException`; non-empty non-`true` → same with `denied=true`; `true` → proceed. |
| `alwaysCreateRevision` | bool | false | Force incremental update even if the PDF has no signatures (§5.1). |
| `pdfVersion` | `2`..`7` | **`7`** | Only affects the header when the file is fully rewritten (`%PDF-1.<v>`); in append mode the version is never changed (§5.2). Out of range → "keep original version" (and disables compression); non-integer → 7. |
| `compressPdf` | `false` disables | enabled | Full compression (object streams + xref stream) only when rewriting the whole file, `pdfVersion > 2` and input is not PDF/A-1 (§5.2). |
| `signReservedSize` | integer bytes | `27000` | Size of the `/Contents` placeholder (bytes of CMS); placeholder literal = `2*size + 2` chars. CMS bigger than this → `AOException("El tamano de la firma (n) supera el maximo permitido para un PDF (m)")`. Non-integer → 27000 (logged). |

### 3.6 Pre-signature document changes: stamp image, attachment

| Key | Type | Default | Effect |
|---|---|---|---|
| `image` | Base64 image (or path if not secure mode) | none | Drawn on page content *before* signing (part of the signed revision) (§5.9). Same normalisation to JPEG as the rubric. Load failure → `IOException("No se pudo cargar la imagen para agregarla al PDF")`. |
| `imagePage` | integer: page number, `-1` last page, `0` all pages | none (**required**) | Unset → image silently not added. Non-integer → `IOException`. Out-of-range page → iText error. |
| `imagePositionOnPageLowerLeftX`/`LowerLeftY`/`UpperRightX`/`UpperRightY` | integers | none (all required) | Image is stretched to this rectangle (no aspect preservation). |
| `attach` | Base64 binary (or path if not secure mode) | none | Embedded file attachment (requires `attachFileName`). Not Base64 → warning, ignored. |
| `attachFileName` | string | none | Attachment file name. |
| `attachDescription` | string | none | Attachment description. |

"Secure mode" path loading (`secureMode == false`, never in AutoFirma desktop): if the value is shorter than 500
characters it is first tried as a URI/path (`AOUtil.createURI` + `loadFile`); for `signatureRubricImage`/`image` a
failure is an `IOException("El parametro de imagen no contiene una ruta valida a un recurso")` (no Base64 fallback
attempted for short values!), for `attach` it falls back to Base64.

### 3.7 Encrypted PDFs, interaction

| Key | Type | Default | Effect |
|---|---|---|---|
| `ownerPassword` | string | none | Password used to open the PDF (tried first). Bytes: platform default charset in `PdfUtil` (`getBytes()`), UTF-8 in `XmpHelper`. Presence forces append mode. |
| `userPassword` | string | none | Used if no `ownerPassword`. A *user* password does not grant full permissions → signing fails with `BadPdfPasswordException` unless it is also the owner password (§9.4). Presence forces append mode. |
| `headless` | bool | false | Passed around but **the PAdES signer never shows dialogs** in this code base; exceptions are thrown instead. Callers (UI, batch) use it to decide whether to prompt. |

### 3.8 Timestamps

All keys are shared with CAdES (`TsaParams`).

| Key | Type / values | Default | Effect |
|---|---|---|---|
| `tsaURL` | URI: `http`, `https` or `socket` scheme | none | No URL → no timestamp at all. |
| `tsType` | `1` signature TS, `2` document TS, `3` both | unset ≈ `1` | Signature TS when `tsType != "2"`; document TS (new `/DocTimeStamp` revision **before** the signature) when `2` or `3` (§7). |
| `tsaPolicy` | OID | `0.4.0.2023.1.1` | `TimeStampReq.reqPolicy`. |
| `tsaHashAlgorithm` | digest name | `SHA-512` | Message imprint algorithm. |
| `tsaRequireCert` | bool-ish | true | `certReq`; only the literal `false` (ignore case) disables. |
| `tsaUsr` / `tsaPwd` | strings | none | HTTP Basic auth if `tsaUsr` non-empty (`Base64(usr + ":" + pwd)`; `pwd` may print as `null`). |
| `tsaExtensionOid` / `tsaExtensionValueBase64` / `tsaExtensionCritical` | OID / Base64 DER / bool | none / none / false | One request extension; both OID and value required. |
| `tsaSslKeyStore` / `tsaSslKeyStorePassword` / `tsaSslKeyStoreType` | Base64 keystore / string / type | none / `""` / `PKCS12` | TLS client authentication. |
| `tsaSslTrustStore` / `tsaSslTrustStorePassword` / `tsaSslTrustStoreType` | Base64 keystore / string / type | none / `""` / `PKCS12` | TLS server trust; **if absent, every server certificate is trusted**. |
| `verifyHostname` | bool | true | `false` disables TLS host name verification. |

**Bug (current source):** both timestamp kinds are broken by a reflection error (§7.4).

### 3.9 Shadow-attack / modification checks (validation; read by `ValidatePdfSignature`, not by the signer)

| Key | Type / values | Default | Effect |
|---|---|---|---|
| `allowShadowAttack` | `true` / other / unset | unset (= check) | `true` disables the PSA check. Unset + relaxed validation → `SuspectedPSAException` (ask user); set to non-`true` → result KO. |
| `pagesToCheckShadowAttack` | integer or `all` | `10` | Number of pages rendered and compared (from page 1). |
| `allowModifiedForm` | `true` / other / unset | unset (= check) | `true` disables the form-field change check (and the PSA check too). |
| `checkCertificates` | bool | false (when `validate(sign, Properties)` is used) | Check validity period of each signing certificate. |
| `checkSignatures` | bool | false | Caller-level (protocol launcher, triphase server): validate existing signatures before signing. |

### 3.10 UI / protocol-only keys (not read by the signer)

| Key | Values | Read by | Effect |
|---|---|---|---|
| `visibleSignature` | `want` \| `optional` | protocol launchers | Show the area-selection dialog; `want` makes cancelling an error (§12.6). |
| `visibleAppearance` | `custom` | protocol launchers | Also show the appearance editor after the area. |
| `serverUrl` | URL | `AOPDFTriPhaseSigner` | Triphase service endpoint (§11). |
| `SignatureId` | string | triphase server | Id of the `TriSign` (default random UUID). |

### 3.11 Aliases / compatibility summary

- `signaturePage` ≡ `signaturePages` (plural wins).
- Format names `Adobe PDF` ≡ `PAdES`; `Adobe PDF TriPhase` ≡ `PAdEStri`.
- `expPolicy=FirmaAGE` (alias of the 1.9 policy). `FirmaAGE19` exists in `policy.properties` but is **rejected**
  by the expander (not in the supported list).
- Legacy spelling `includeOnlySignningCertificate` is the only spelling.
- There are **no** keys named `signatureFieldVisibility`, `checkShadowAttack`, `pagesToCheck` or "exclude images" in
  this code base; the corresponding concepts are `signatureField` (+ zero-size rect), `allowShadowAttack`,
  `pagesToCheckShadowAttack` and none.

### 3.12 `signTime` parsing

`new SimpleDateFormat("yyyy:MM:dd:HH:mm:ss").parse(value)` in the JVM default time zone, lenient (Java default:
`2010:13:40:…` rolls over). Failure → current time.

---

## 4. Parameter normalisation inside `PdfSessionManager.getSessionData`

Executed for every pass (pre and post), in this order:

1. Read `doNotUseCertChainOnPostSign`, `signatureRotation` (`Integer.parseInt`, default `"0"`), rubric image (§3.4,
   loaded/normalised *before* anything else, so a bad image fails early), `signReason`, `signatureField`,
   `signatureProductionCity`, `signerContact`.
2. XMP history (§5.10) — may rewrite the input bytes. `BadPasswordException` here → `BadPdfPasswordException` if a
   password param was given, else `PdfIsPasswordProtectedException("El PDF esta protegido contra lectura")`. Any
   other error → warning, original bytes kept.
3. Open `PdfReader` (§9.4).
4. Sub-filter forcing (policy or `profile` = `baseline`, case-sensitive here).
5. `certificationLevel`, `pdfVersion` (§3.5).
6. PDF/A-1 detection: XMP (whitespace stripped) contains `<pdfaid:part>1</pdfaid:part>`.
7. If visible: compute obfuscation flag, layer4 text, layer2 text (default text if none and no rubric), font
   (`getFont(family, size, style, color, pdfA1)`).
8. `checkPdfCertification` (§9.3), unregistered signatures (§9.2).
9. `reader.removeUsageRights()` — removes `/Perms /UR` and `/UR3` (Reader-extension usage rights, which iText would
   break anyway); removes `/Perms` if it becomes empty.
10. `PdfStamper.createSignature(reader, out, pdfVersionChar or '\0', tempFile=null, appendMode, signTime)` (§5.1).
    `BadPasswordException` → `BadPdfPasswordException("La contrasena del PDF es incorrecta")` if a password was given,
    else `PdfIsPasswordProtectedException("El PDF esta protegido contra modificaciones")`. `DocumentException` →
    `AOException("Error al crear la firma para estampar")`.
11. Pages / new page / position correction (§3.3).
12. Compression (§5.2), appearance mode (`includeQuestionMark`), `enableLtv` (no visible effect, §5.2), attachment,
    stamp image, render mode `SignatureRenderDescription`, reason/location/contact/date/crypto on the appearance.
13. Rubric / text layers / rotation (§8), `setVisibleSignature`.
14. Build the signature dictionary (§5.3), certification level, PDF version, reserve `/Contents`, `preClose(…)`
    (writes the revision with placeholders), return session `(appearance, outputBuffer, fileID string)`.

---

## 5. PDF structure written

### 5.1 Revision strategy (`PdfUtil.getAppendMode`)

```
append = ownerPassword set || userPassword set
         || alwaysCreateRevision == "true"
         || AcroFields.getSignatureNames().size() > 0      # signatures incl. DocTimeStamps (§9.1)
```

| Situation | Output |
|---|---|
| `append == true` (normal co-signing, encrypted input, forced) | **Incremental update**: the original bytes are copied verbatim, then `\n` (a single LF) and the new objects, a new xref section (table or stream, §5.2) with `/Prev`, `startxref`, `%%EOF\n`. *Observed:* original file is an exact prefix of the output. |
| `append == false` (first signature on an unsigned, unencrypted PDF) | **Full rewrite** of the document by iText (objects renumbered, unused objects dropped, header rewritten). Earlier revisions of the input are lost. Rationale (code comment): many PDF 1.3 files produced by QPDF etc. have garbage after `%%EOF`, which breaks append mode. |

In append mode iText refuses "rebuilt" documents (xref was broken and had to be reconstructed): `DocumentException
("Append mode requires a document without errors even if recovery was possible.")` → `AOException` (code `212002`).
**Gotcha:** a PDF with an existing signature and a damaged xref therefore cannot be co-signed.

### 5.2 Header, version, compression, catalog extras, Info, IDs

- **Full rewrite:** header `%PDF-1.<v>\n%\xE2\xE3\xCF\xD3\n` with `v = pdfVersion` (default **7**, so the output is
  always `%PDF-1.7` by default — *observed*); `pdfVersion` invalid/out of range → original version kept.
  Full compression (`stp.setFullCompression()`) when `pdfVersion > 2 && !pdfA1 && compressPdf != "false"`
  (case-insensitive): objects (except the signature dictionary and streams) go into object streams (iText:
  ≤ 200 objects per `/ObjStm`), cross-reference **stream** (`/Type/XRef /W[1 3 2]`). **Quirk:** compression calls
  `setAtLeastPdfVersion('5')` *after* the header was written, so `pdfVersion=4` yields a `%PDF-1.4` header with xref
  streams (*observed*). Otherwise a classic `xref` table + `trailer`.
- **Append mode:** header untouched; the appended section starts with `\n`. Compression is decided by the input:
  xref stream if the input's last xref is a stream (and not hybrid), else a classic table. `setFullCompression` is a
  no-op. **The PDF version is never bumped**: iText's stamper never writes the catalog `/Version`.
- `PdfUtil.enableLtv` calls `addDeveloperExtension(/ESIC, BaseVersion /1.7, ExtensionLevel 1)`, but the iText
  stamper never writes catalog `/Extensions` either → **no `/Extensions` dictionary is produced** (*observed*). A 1:1
  port must not write it.
- The `/Pages` root dictionary always gets `/ITXT (2.1.7)` (so it is rewritten in every incremental update).
- `/AcroForm`: `/NeedAppearances` removed (if present); `/SigFlags 3`; `/Fields` gets the new field; if missing,
  `/DA (/Helv 0 Tf 0 g )` and `/DR /Font` entries `/Helv` (`<</Type/Font/BaseFont/Helvetica/Encoding/WinAnsiEncoding
  /Name/Helv/Subtype/Type1>>`) and `/ZaDb` (`<</Type/Font/BaseFont/ZapfDingbats/Name/ZaDb/Subtype/Type1>>`) are
  added; the appearance resources of the new field (`/XObject << /FRM n 0 R >>`) are merged into `/DR`.
- **Info dictionary:** old entries copied; `/ModDate` = signTime as PDF date (§5.4); `/Producer` is **not** changed
  (*observed*). In append mode it is written with its original object number.
- **XMP metadata** (if the catalog has a `/Metadata` stream): parsed with iText `XmpReader`; `xmp:ModifyDate` is
  replaced (or added to the `http://ns.adobe.com/xap/1.0/` description) with the W3C date of signTime, and
  `xmp:MetadataDate` replaced if present; re-serialised; in append mode written under the same object number. Parse
  failure → original bytes kept.
- **Trailer `/ID`:** unencrypted: **both** elements newly generated: each = MD5(`currentTimeMillis + "+" +
  freeMemory + "+" + seq++`) (two different values), written `[<32 lowercase hex><32 lowercase hex>]`. Encrypted:
  first element = the original document ID (needed for the encryption key), second element new random. This string
  is the triphase "file ID" (§11).

**Number formatting** (iText `ByteBuffer.formatDouble`, `HIGH_PRECISION = false`), used for every real number
written (Rect, BBox, Tm, cm, rg…): `|d| < 0.000015` → `0`; `|d| < 1` → rounded (half-up, `+0.000005`) to 5 decimals,
trailing zeros removed (`0.50196`, `0.21256`); `|d| ≤ 32767` → rounded to 2 decimals (`+0.005`), trailing zeros
removed (`189.44`, `14.56`, `66`); larger → integer (rounded). Integers as plain decimals.

### 5.3 Signature dictionary and byte range

Written as an **indirect object, never inside an object stream**. Its object number is reserved first (object `1`
in a full rewrite, the first new number in append mode); with full compression it is the first object in the file
(*observed* offset 15), otherwise it may follow objects written earlier (e.g. the widget). Key order (iText `PdfDictionary` is a
`LinkedHashMap`):

```
<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/<subfilter>
  /M(<PdfDate>)                          # always (signTime)
  /Name(<CN of signing cert>)            # unless doNotUseCertChainOnPostSign; iText PdfPKCS7.getSubjectFields(cert).getField("CN")
  /Reason(...)/Location(...)/ContactInfo(...)   # each only if set
  /ByteRange <80-byte literal>
  /Contents <placeholder literal>
  /Reference[...]                        # only if certificationLevel > 0 (§5.7)
>>
```

*Observed (default parameters):*
`<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/ETSI.CAdES.detached/M(D:20261016133534+02'00')/Name(PEREZ GARCIA JUAN - 12345678Z)/ByteRange [0 249 54251 83968 ]<60 spaces>/Contents <54000 hex digits>>>`

- Text strings (`/Name`, `/Reason`, `/Location`, `/ContactInfo`) use iText `TEXT_UNICODE`: PDFDocEncoding if every
  char is representable, else UTF-16BE with BOM `FE FF`; written as literal `(...)` strings with escaping. Encrypted
  documents: these strings (and `/M`) are encrypted with the object key; `/Contents` is **not** encrypted.
- Because the reserved values are `PdfLiteral`s, the serializer writes a **space** between key and value for
  `/ByteRange` and `/Contents` (`/ByteRange [`, `/Contents <`), but not for names/strings/arrays elsewhere.
- **`/ByteRange` reservation:** exactly **80 bytes** of spaces. Final content: `[` + for each of the 4 integers:
  decimal + one space + `]`, left-aligned, remaining bytes stay spaces. E.g. `[0 249 54251 83968 ]` + 60 spaces.
- **`/Contents` reservation:** `exc[/Contents] = 2*S + 2` bytes with `S = signReservedSize` (default 27000 → 54002
  bytes). Final content: `<` + lowercase hex of the CMS, **right-padded with `00` bytes to S bytes** (i.e. trailing
  `0` hex digits) + `>`. (The document timestamp uses the same reservation, §7.3.)
- **Byte range:** `[0, a, b, L − b]` where `a` = offset of the `<` of `/Contents`, `b = a + 2S + 2` (just after `>`),
  `L` = final file length. The hashed data = `bytes[0..a) ‖ bytes[b..L)`.
- `/M` and Info `/ModDate` use `PdfDate` (§5.4).

### 5.4 Date format (`PdfDate`)

`D:YYYYMMDDHHmmSS` (local fields of the Calendar) followed by:
`tzHours = (ZONE_OFFSET + DST_OFFSET) / 3600000` (integer division, truncation toward zero);
`tzHours == 0` → `Z`; else `+` or `-`, `|tzHours|` 2 digits, `'`, minutes `= |offsetMinutes| − |tzHours|*60` 2 digits,
`'`. Example `D:20261016133534+02'00'`. **Quirk:** offsets between −1h and 0 (e.g. −00:30) print `Z`.
W3C form (XMP): `YYYY-MM-DDTHH:mm:ss+HH:MM` / `Z`.

### 5.5 Signature field and widget

**New field** (no `signatureField`): a single merged field/widget dictionary (written once, may be in an object
stream):

```
<</FT/Sig/T(Signature<n>)/V <sigdict ref>/F 132/Type/Annot/Subtype/Widget/Rect[llx lly urx ury]
  /AP<</N <appearance ref>>>/P <page ref>/DR<</XObject<</FRM <frm ref>>>>>>
```
(*observed*; for invisible signatures `/Rect[0 0 0 0]` and `/DR<<>>`)

- Name: `Signature<k>` with the smallest k ≥ 1 such that no field named `Signature<k>` exists, no field name starts
  with `Signature<k>.`, and (patched iText) no AcroForm field (`PRAcroForm` list) is named `Signature<k>` or starts
  with `Signature<k>.`.
- `/F 132` = Print (4) | Locked (128).
- `/Rect`: the (normalised) rectangle; numbers printed by iText with at most 2 decimals. If the main page has
  `/Rotate` 90/180/270 the rect `(left, bottom, right, top)` given in displayed space is transformed into unrotated
  page space (only for the first page the annotation is added to), with `W = pageSizeWithRotation.right`,
  `H = pageSizeWithRotation.top`, written as the 4 numbers `(x1, y1, x2, y2)` exactly as computed — **not normalised** (*observed*
  `/Rect[495 100 415 300]` for the box (100,100)-(300,180) on a `/Rotate 90` A4 page):
  - 90: `(H − bottom, left, H − top, right)`;
  - 180: `(W − left, H − bottom, W − right, H − top)`;
  - 270: `(bottom, W − left, top, W − right)`.
- `/P` = the **first** page in the page list.
- Invisible signature (no visible area, no field): `/Rect [0 0 0 0]`, appearance = empty form XObject with
  `/BBox[0 0 0 0]`, added to **page 1** (the appearance's default page).
- **Multi-page quirk (observed):** for a page list `[p1, p2, …]` iText adds the *same* widget object to each page's
  `/Annots` array, and appends the *same* reference to `/AcroForm /Fields` once **per page** (e.g.
  `/Fields[7 0 R 7 0 R 7 0 R 7 0 R]`). `/P` points to `p1`; the rotation fix-up of `/Rect` uses `p1` only. A 1:1 port
  reproduces this (it is what viewers have been seeing); a "clean" alternative would be one widget per page as kids of
  one field.
- `/Annots`: if the page has no `/Annots` array a direct one is created in the page dictionary; if it is an indirect
  array, that array object is rewritten.

**Existing field** (`signatureField` given, `setVisibleSignature(fieldName)`): the field's *value* dictionary
(`AcroFields.Item.getValue(0)`) gets `/V <sigdict ref>`; its *widget* (`getWidget(0)`) gets `/P <page ref>`,
`/F = oldF | 128` (old F or 0), `/AP << /N <appearance> >>`. Rect/page come from the field (first widget); for a
rotated page the rect is mapped back into displayed space for the appearance size. *Observed:* `/F 4` → `/F 132`.
Field names containing `.` cannot be *created* (only used).

### 5.6 Appearance streams (layers)

Built by `PdfSignatureAppearance.getAppearance()` (patched: `TOP_SECTION = 0`, `MARGIN = 2`). With
`acro6Layers = true` (default, `includeQuestionMark` unset):

```
AP /N  = form XObject "napp":  BBox = rect (rotated if page rotated), content "q 1 0 0 1 0 0 cm /FRM Do Q\n"
  FRM  = form XObject:         BBox = rect (rotated), content:
                                 [rotation CTM if page /Rotate ≠ 0]
                                 "q 1 0 0 1 0 0 cm /n0 Do Q\nq 1 0 0 1 0 0 cm /n2 Do Q\n"
    n0 = form XObject: BBox [0 0 100 100], content "% DSBlank\n"
    n2 = form XObject: BBox [0 0 w h] (w,h = rect size), the visible content (§8)
```

All form XObjects: `<</Type/XObject/Subtype/Form/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI] …>>/BBox[…]
/FormType 1/Matrix [1 0 0 1 0 0]/Length n/Filter/FlateDecode>>` (iText default compression level). Resource names:
fonts `/F1`, `/F2`…, images `/img0`…, templates `/Xf1`… (unnamed) or forced names `n0`..`n4`, `FRM`.

Page-rotation CTM at the very start of FRM, not wrapped in `q/Q` (w, h = field size *as displayed*; FRM and napp
BBoxes are the rect rotated by the page rotation, e.g. `[0 0 80 200]` for a 200×80 box on a 90° page): 90 →
`0 1 -1 0 h 0 cm\n`; 180 → `-1 0 0 -1 w h cm\n`; 270 → `0 -1 1 0 0 w cm\n`, so the appearance reads upright on the
displayed page (*observed* `0 1 -1 0 80 0 cm` + the two `Do` lines).

With `includeQuestionMark=true` (acro6Layers false): FRM draws `n0`, `n1` (scaled), `n2`, `n3` (scaled), `n4`:
`n1` = iText's question-mark glyph program (BBox `[0 0 100 100]`, starts with `% DSUnknown`), `n3` = `% DSBlank`,
both drawn with `q s 0 0 s x y cm` where `s = min(w,h)*0.9/100`, `x = (w − 100s)/2`, `y = (h − 100s)/2`
(*observed* `q 0.72 0 0 0.72 64 4 cm` for 200×80); `n4` BBox `[0 h w h]` (zero height because TOP_SECTION = 0)
containing layer-4 text fitted between size limits (max 15). Viewers do not render a zero-height n4 meaningfully.

### 5.7 Certification (DocMDP)

When `certificationLevel = P ∈ {1,2,3}` the signature dictionary gets (*observed*):

```
/Reference[<</TransformMethod/DocMDP/Type/SigRef
             /TransformParams<</P P/V/1.2/Type/TransformParams>>
             /DigestValue(aa)/DigestLocation[0 0]/DigestMethod/MD5
             /Data <catalog ref>>>]
```
and the catalog gets `/Perms << /DocMDP <sigdict ref> >>` (replacing any existing `/Perms`). The bogus
`DigestValue/DigestLocation/DigestMethod` entries are iText 2.1.7 legacy — replicate for parity (viewers ignore them).

### 5.8 Encryption

Encrypted input (any password param or encrypted file) is always signed in append mode with the *original* encryption
(`PdfEncryption(reader.getDecrypt())`, `/Encrypt` reference reused). New strings and streams are encrypted; the
signature `/Contents` hex string is not. The output remains encrypted with the same passwords (*observed* with RC4 and
AES-256 test files). Certificate (public-key) encryption can be opened only with a certificate (not supported by
AutoFirma's API).

### 5.9 Stamp image and attachment (inside the signed revision)

- `image`: for each target page `getOverContent(page).addImage(image, w, 0, 0, h, llx, lly, inline=false)` with
  `w,h,llx,lly` = `(int)` of the image rectangle → page `/Contents` becomes an array with an added `q`-prefixed
  stream before and the image stream after (iText `PageStamp` "over content": `q` … `Q`, image XObject `/img0` in the
  page resources, `q w 0 0 h x y cm /img0 Do Q`). Image XObject: `/Subtype/Image/Filter/DCTDecode/ColorSpace/DeviceRGB
  /BitsPerComponent 8`. **Gotcha:** in append mode this modifies already-signed pages → shadow-attack checks will flag
  the document; the desktop UI disables stamps for co-signing.
- `attach`: `PdfWriter.addFileAttachment(description, bytes, null, fileName)` → file specification
  `<</Type/Filespec/F(fileName)/UF(fileName)/EF<</F s/UF s>>/Desc(description)>>` (`/UF` PDFDocEncoding, `/Desc`
  text string, `description = ""` when null) and embedded stream `s` = `<</Type/EmbeddedFile/Params p/Filter
  /FlateDecode …>>` (best compression) with `p = <</Size rawLength>>`. Added to the catalog `/Names /EmbeddedFiles`
  name tree (existing tree read and rewritten as a new object); tree key = description, or `Unnamed` if empty, with
  ` 1`, ` 2`… appended on collisions.

### 5.10 XMP signature history (PDF/A only)

`XmpHelper.addSignHistoryToXmp(pdf, signTime, params)` runs **before** signing, on every pass:

1. Open with password (owner, else user; UTF-8 bytes). If encrypted → no change.
2. If XMP does not contain `<pdfaid:part>` (any PDF/A part) **or** the PDF is already signed (`isSign`) → no change.
3. New history item:
```
<rdf:li rdf:parseType="Resource">
  <stEvt:action>signed</stEvt:action>
  <stEvt:instanceID>uuid:<UUID.nameUUIDFromBytes(BigInteger.valueOf(signTimeMillis).toByteArray())></stEvt:instanceID>
  <stEvt:parameters>Firmado por el Cliente @firma</stEvt:parameters>
  <stEvt:softwareAgent>Cliente @firma</stEvt:softwareAgent>
  <stEvt:when><W3C signTime></stEvt:when>
</rdf:li>
```
(UUID v3 = MD5 name-based over the two's-complement big-endian minimal bytes of the millisecond value.)
4. If exactly one `xmpMM:History` exists: append to its `rdf:Seq` (or, if it has no `rdf:Seq`, append
   `<rdf:Seq xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#">…</rdf:Seq>` to the **first**
   `xmpMM:History` of the document). Else: requires exactly one `pdfaid:conformance` element (else
   `IllegalStateException("El PDF no tiene una entrada RDF XMP valida")` → caught upstream, original kept) and appends
   `<xmpMM:History xmlns:rdf=… xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stEvt=…><rdf:Seq>item</rdf:Seq>
   </xmpMM:History>` to its parent `rdf:Description`.
5. Serialise (DOM LS, namespaces off, canonical form if supported), restore the original XML header (text up to the
   first `?>`) and the original trailer (from the last `<?`, i.e. the `<?xpacket end=…?>`).
6. **Quirk:** dates are fixed with global string replacement: the old `xmp:ModifyDate` value is replaced **everywhere**
   by the W3C signTime, then the (possibly already replaced) `xmp:CreateDate` value is replaced everywhere by the Info
   `/CreationDate` (W3C). When the original CreateDate equals ModifyDate this rewrites `stEvt:when` to the creation
   date (*observed*). Replicate or fix.
7. Write with a **non-append** `PdfStamper(reader, out, signTime)` + `setXmpMetadata` (a full rewrite of the
   unsigned document), then signing proceeds on these bytes.

---

## 6. CMS / CAdES inside `/Contents`

### 6.1 Data hashed

`messageDigest = H(byteRange bytes)` where `H` = digest of the signature algorithm (`getDigestAlgorithmName`, e.g.
`SHA256withRSA` → `SHA-256`).

### 6.2 SignedData (`CAdESTriPhaseSigner.postSign`, *observed*)

```
ContentInfo {
  contentType  id-signedData (1.2.840.113549.1.7.2)
  content [0] SignedData {
    version            1
    digestAlgorithms   SET { AlgorithmIdentifier{ digestOID, NULL } }
    encapContentInfo   { id-data (1.2.840.113549.1.7.1) }           -- no eContent (detached)
    certificates  [0]  the chain (or only signer cert), DER-sorted SET
    -- no crls
    signerInfos  SET { SignerInfo {
        version 1
        sid      IssuerAndSerialNumber (issuer from the cert TBS, serial)
        digestAlgorithm  { digestOID, NULL }
        signedAttrs [0]  (§6.3)
        signatureAlgorithm  RSA: { rsaEncryption 1.2.840.113549.1.1.1, NULL }
                            otherwise: { OID of the full signature algorithm (e.g. ecdsa-with-SHA256
                                         1.2.840.10045.4.3.2), NULL }       -- NULL even for ECDSA (replicate)
        signature  OCTET STRING (PKCS#1 v1.5 RSA / DER ECDSA-Sig-Value)
        [unsignedAttrs [1]  signature timestamp, §7.2]
    } }
  }
}
```
Encoded DER (`getEncoded(DER)` → every SET OF sorted by DER rules). Digest OIDs: SHA1 `1.3.14.3.2.26`, SHA-256
`2.16.840.1.101.3.4.2.1`, SHA-384 `…2.2`, SHA-512 `…2.3`.

### 6.3 Signed attributes (exact list)

`CAdESParameters.load(null, algo, params)` then PAdES overrides: `dataDigest = H(range)`, `metadata = null`,
`contentTypeOid = null`, `contentDescription = null`, `signingTime = null`. Resulting attributes (then DER-sorted as a
SET):

| Attribute | OID | Present | Value |
|---|---|---|---|
| contentType | 1.2.840.113549.1.9.3 | always | `id-data` |
| messageDigest | 1.2.840.113549.1.9.4 | always | OCTET STRING H(range) |
| signingCertificateV2 | 1.2.840.113549.1.9.16.2.47 | V2 rule §3.1 | `SigningCertificateV2 { certs: [ESSCertIDv2 { hashAlgorithm **omitted when SHA-256** else {OID, NULL}, certHash = H(cert DER), issuerSerial { GeneralNames{ directoryName(issuer) }, serial } }], policies: cert policies (unless `doNotIncludePolicyOnSigningCertificate`) }` |
| signingCertificate (v1) | 1.2.840.113549.1.9.16.2.12 | otherwise | `SigningCertificate { [ESSCertID { certHash = H(cert) with the **signature digest** (even if not SHA-1), issuerSerial }], [policies] }` |
| sigPolicyId | 1.2.840.113549.1.9.16.2.15 | `policyIdentifier` | `SignaturePolicyId { sigPolicyId OID, sigPolicyHash { {hashOID, NULL}, OCTET STRING(hash or 0x00 if none) }, [sigPolicyQualifiers SEQUENCE{ SigPolicyQualifierInfo{ id-spq-ets-uri, IA5String } }] }` |
| commitmentType | 1.2.840.113549.1.9.16.2.16 | §3.1 | one attribute **per** indication |
| signer-attributes / -v2 | …2.18 / 0.4.0.19122.1.1 | `signerClaimedRoles` | §3.1 |
| mimeType | 0.4.0.1733.2.1 | `includeMimeTypeAttribute=true` | §3.1 |
| ~~signingTime~~ | — | **never** | (PAdES: time is in `/M`) |
| ~~contentHints~~, ~~signerLocation~~ | — | never | |

Default result for an RSA/SHA-256 signature: `{contentType, messageDigest, signingCertificateV2}` (*observed*).

### 6.4 What is signed

The pre-sign is `DER(SET OF Attribute)` with the universal SET tag `0x31` (as required by CMS); it is placed in the
SignerInfo with implicit tag `[0]`. `AOPkcs1Signer.sign(preSign, algo, key)` = standard `Signature(algo)` over those
bytes.

### 6.5 Size

The CMS must fit in `signReservedSize` (27000) bytes, else `AOException(212002)`.

### 6.6 Enhancer hook

If an enhancer class is configured in `/enhancer.properties` (`enhancerClassFile`), the CMS is passed through
`enhancer.enhance(cms, enhancerConfig ?: extraParams)` after the timestamp step (e.g. to upgrade via an @firma
platform). Not configured in AutoFirma; a Rust port can expose an optional hook.

### 6.7 Not produced

No `/DSS`, no VRI, no `/Prop_Build`, no revocation data (`adbe-revocationInfoArchival`), no CRLs/OCSP in the CMS.
Output is at most PAdES-B-B (or B-T if timestamps worked); LTV levels are never generated.

---

## 7. Timestamps (`PdfTimestamper`, `CMSTimestamper`)

### 7.1 `tsType`

`TS_LEVEL_SIGN = "1"`, `TS_LEVEL_DOC = "2"`, `TS_LEVEL_SIGN_DOC = "3"`. Signature timestamp: `tsaURL != null &&
tsType != "2"` (so unset counts as 1). Document timestamp: `tsaURL != null && tsType ∈ {"2","3"}`.

### 7.2 Signature timestamp (intended behaviour)

After building the CMS: for each SignerInfo, imprint = `H_tsa(signature value octets)`; request the token (§7.5);
add unsigned attribute `id-aa-signatureTimeStampToken` (`1.2.840.113549.1.9.16.2.14`) = `SET { TimeStampToken }`,
**replacing** all unsigned attributes; re-encode (`CMSSignedData.replaceSigners(...).getEncoded()`). Any failure is
only logged and the un-timestamped CMS is used.

### 7.3 Document timestamp (intended behaviour)

Applied to the input **before** the signature (so the order of revisions is: DocTimeStamp, then signature — unlike
PAdES-LTA, where the doc timestamp comes last):

1. Open reader (passwords), `checkPdfCertification` (§9.3), `pdfVersion` like §3.5.
2. `createSignature(..., getAppendMode(...), signTime)`; compression only if `pdfVersion >= 5` and `compressPdf !=
   false` (no PDF/A test here).
3. Dictionary `<</Type/DocTimeStamp/Filter/Adobe.PPKLite/SubFilter/ETSI.RFC3161/M(date)/ByteRange …/Contents …>>`,
   invisible widget (`Signature<n>`, `/Rect[0 0 0 0]`, page 1), `/Contents` reserved `2*signReservedSize+2`.
4. Imprint = `H_tsa(byte range)`; token = `TimeStampToken` DER (the full CMS from the response); must be ≤ 27000
   bytes (hard-coded `CSIZE`, independent of `signReservedSize`); padded with zeros to 27000 bytes (**Gotcha:** if
   `signReservedSize < 27000` the close fails "too big").
5. The signature is then added on top (append mode, since the doc timestamp is a "signature").

### 7.4 **Bug: timestamps are non-functional in this source revision**

`PdfTimestamper.buildCmsTimeStamper` does `cmsTimestamperClass.getConstructor(tsaParamsClass.getClass())`, i.e.
looks up a constructor taking `java.lang.Class` instead of `TsaParams`. Result (*observed*):
- Signature TS: `NoSuchMethodException` caught → warning `No se ha podido actualizar la firma` → **signature without
  timestamp**, no error reported.
- Document TS (`tsType` 2/3): `InvalidLibraryException("Error con las bibliotecas de composicion del sello de tiempo
  para firmas PDF")` (code `200002`) → **signing fails**.

A Rust port should implement the intended behaviour (§7.2/§7.3) and document the divergence, or offer a
"Java-compat" switch.

### 7.5 RFC 3161 request/transport (`CMSTimestamper`)

- `TimeStampReq { version 1, messageImprint { hashAlgorithm OID(tsaHashAlgorithm) (BC default params), imprint },
  reqPolicy = tsaPolicy (default 0.4.0.2023.1.1), nonce = INTEGER(signTime millis), certReq = tsaRequireCert,
  extensions = [optional single extension] }`.
- `http`/`https`: POST body = DER request; headers `Content-Type: application/timestamp-query`,
  `Content-Transfer-Encoding: binary`, optional `Authorization: Basic …`. Response body; if the response
  `Content-Encoding` header is `base64` (ignore case) → Base64-decoded. HTTPS: TLS context with optional client key
  store, trust store or trust-all, optional host-name verification disable.
- `socket://host:port`: raw TCP (RFC 3161 §3.3 style): write int32 BE `len+1`, byte `0`, request; read int32 `size`,
  byte flag, `size-1` bytes; flag must be 5 or 6 else `IOException`. Socket timeout 500000 ms.
- Response: `TimeStampResponse(raw)`, `validate(request)` (nonce, imprint, policy, status), `failInfo` must be 0, token
  must exist. Errors → `AOException` codes `TSA_CONNECTION_ERROR` / `GENERATING_TIMESTAMP_ERROR`.

---

## 8. Visible appearance (layer n2 content)

### 8.1 Decision table

| Inputs | n2 content |
|---|---|
| visible, no rubric, no `layer2Text` | default text (§8.3) |
| visible, `layer2Text` set (possibly empty) | that text (resolved) |
| visible, rubric, no `layer2Text` | rubric only ("signature with image only") |
| visible, rubric + `layer2Text` | rubric (best fit, centred), then text on top |
| `signatureRotation ≠ 0` (new area only) | one pre-rotated template containing rubric + text (§8.7); text auto-shrinks |
| existing field (`signatureField`) | text only (default or `layer2Text`); **rubric and rotation ignored**; with rubric and no `layer2Text` the field is blank (**Gotcha**) |
| invisible | empty appearance |

### 8.2 Template tokens (`PdfVisibleAreasUtils.getLayerText`)

Applied to `layer2Text` and `layer4Text`, in this order (plain `String.replace`, all occurrences):

With a certificate (`chain[0]`), `principal = cert.getSubjectX500Principal().toString()` (Java RFC 1779-style
string: RDNs in reverse encoding order, `", "` separators, keywords `CN, C, L, ST, O, OU, T, IP, STREET, DC,
DNQUALIFIER, DNQ, SURNAME, GIVENNAME, INITIALS, GENERATION, EMAILADDRESS, UID, SERIALNUMBER`, other attributes as
`OID.x.y.z=`, values with special characters quoted):

| Token | Value |
|---|---|
| `$$SUBJECTCN$$` | `AOUtil.getCN(cert)` (CN, else first OU, else first RDN value), **obfuscated** if enabled. **Gotcha:** NPE if null. |
| `$$ISSUERCN$$` | `AOUtil.getCN(cert.getIssuerX500Principal().getName())` — note RFC 2253 string (no spaces, escaped). Never obfuscated. |
| `$$CERTSERIAL$$` | serial number in **decimal** (`BigInteger.toString()`). |
| `$$PSEUDONYM$$` | value of `OID.2.5.4.65` in `principal`; **replaced only if present** (otherwise the literal token stays in the text). |
| `$$OU$$` | first OU (or empty) |
| `$$OUS$$` | all OUs in `principal` order joined with `", "` (or empty) |
| `$$TITLE$$` | value of `T` (title) or empty |
| `$$SUBJECTDN$$` | `principal`, **obfuscated** if enabled |
| `$$GIVENNAME$$`, `$$SURNAME$$`, `$$ORGANIZATION$$` | `GIVENNAME`, `SURNAME`, `O` values looked up in the (possibly **obfuscated**) principal, or empty |
| `$$REASON$$`, `$$LOCATION$$`, `$$CONTACT$$` | `signReason`, `signatureProductionCity`, `signerContact` or empty (also without certificate) |
| `$$SIGNDATE=<pattern>$$` | signTime formatted with Java `SimpleDateFormat(pattern)` in the **JVM default locale and time zone**; invalid pattern → `new SimpleDateFormat()` (locale default short pattern, e.g. `d/M/yy, H:mm` for es-ES on Java 9+). `$$SIGNDATE$$` (no `=`) → default pattern. Loop: find `$$SIGNDATE`, tag ends at the next `$$` after it; the pattern = tag without `$$`, split on `=`, element [1] (a pattern containing `=` is truncated). A missing closing `$$` throws `StringIndexOutOfBoundsException` (signing fails). |

RDN value lookup (`AOUtil.getRDNvalueFromLdapName(rdn, principal)`): case-insensitive search for `rdn` preceded by
start, `,` or space, followed by optional spaces, `=`, optional spaces; value up to the next `,` (or quoted
`"…"`). See `07-core.md` §7.2. A Rust port must reproduce Java's `X500Principal.toString()` format, otherwise
`$$SUBJECTDN$$`, `$$GIVENNAME$$`, `$$OUS$$` etc. differ.

### 8.3 Default text

Used when `layer2Text` is unset and there is no rubric (`PdfSessionManager.getDefaultLayer2Text`):

```
Firmado por $$SUBJECTCN$$
Fecha: $$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$
Motivo: $$REASON$$                 (only if signReason set)
Lugar de firma: $$LOCATION$$       (only if signatureProductionCity set)
```
(`z` = short time-zone name, e.g. `CEST`.) *Observed rendering* in a 200×80 box with Courier 12:
`Firmado por PEREZ GARCIA` / `JUAN - ***4567**` / `Fecha: 16/10/2026 13:36:29` / `CEST` / `Motivo: Prueba` /
`Lugar de firma: Madrid`.

(iText's own fallback text — only reachable if AutoFirma passes no text, which it never does for visible
signatures — is identical without tokens.)

### 8.4 Obfuscation (`PdfTextMask`, `obfuscateIds`)

Default mask: char `*`, `minLength = 3`, `positions = [F,F,F,T,T,T,T]` (show digits 4–7), `shift = true`.

`parseParam("c;n;b1,b2,…;shift")`: exactly 4 `;`-fields else `IllegalArgumentException`; `c` must be one char; `n`
all digits; positions list must have > 1 element; trailing `false` values are dropped; if the last `true` is at index
0 (or none) the positions stay **default** (silently); shift = `Boolean.parseBoolean`.

`obfuscateIds(text, mask)` (verbatim semantics):
```
digitCount = 0; pos = 0; found = false
for i in 0..len(text):
    c = text[i]
    if isLetterOrDigit(c):
        if isDigit(c):
            digitCount += 1
            if digitCount == mask.minLength: found = true
        else:
            digitCount = 0
    else:                                   # separator (NB: digitCount is NOT reset here)
        if found: obfuscate(text, pos, i - pos, mask); found = false
        pos = i + 1
if found: obfuscate(text, pos, len - pos, mask)

obfuscate(text, pos, length, mask):
    numDigits   = number of digits in the WHOLE text (not the segment!)       # quirk
    plain       = number of true in mask.positions
    if numDigits >= plain:
        pm = mask.positions
        if mask.shift and numDigits < len(pm):
            pm = new bool[numDigits]; omit = len(mask.positions) - numDigits; cnt = 0
            for i, v in enumerate(mask.positions):
                if v or cnt >= omit: pm[i - cnt] = v
                else: cnt += 1
        j = 0
        for k in 0..length:
            ch = text[pos+k]
            if isDigit(ch):
                if j >= len(pm) or not pm[j]: text[pos+k] = mask.char
                j += 1
            else:
                text[pos+k] = mask.char                     # letters/other chars in the segment are hidden
    else:                                                   # apply from the end
        p = len(mask.positions) - 1
        for k from pos+length-1 down to pos:
            if p < 0 or not mask.positions[p]: text[k] = mask.char
            p -= 1
```
Example (*observed*): `PEREZ GARCIA JUAN - 12345678Z` → `PEREZ GARCIA JUAN - ***4567**`;
`SERIALNUMBER=IDCES-12345678Z` → `SERIALNUMBER=IDCES-***4567**`. Java `Character.isDigit/isLetterOrDigit` are
Unicode-aware.

### 8.5 Fonts, styles, colours

| `layer2FontFamily` | Normal documents | PDF/A-1 input |
|---|---|---|
| 0 (default), 3, 4, other | Type1 standard `Courier`, `WinAnsiEncoding`, not embedded: `<</Type/Font/Subtype/Type1/BaseFont/Courier/Encoding/WinAnsiEncoding>>` (*observed*, no `/Widths`) | `/fonts/courier.ttf` (GNU FreeFont FreeMono), `Identity-H`, **fully embedded** (no subset), Type0 + CIDFontType2 + ToUnicode |
| 1 | `Helvetica` | `/fonts/helvetica.ttf` (FreeSans) |
| 2 | `Times-Roman` | `/fonts/times.ttf` (FreeSerif) |

Font loading failure → iText `Font(family, size, style)` without explicit base font (logged).

- Encoding: characters not in Windows-1252 are **silently dropped** with the standard fonts (iText CP1252 converter).
- Bold (bit 1) and italic (bit 2) never select bold/italic font programs; they are simulated per text chunk:
  bold → `2 Tr` (fill+stroke) with line width `size/30` and stroke colour = text colour; italic → text matrix with
  skew `1 0 0.21256 1 x y Tm`. *Observed* (Helvetica 8, bold+italic, red):
  `1 0 0.21256 1 2 70 Tm /F1 8 Tf 2 Tr 0.26667 w 1 0 0 RG 1 0 0 rg (…)Tj 0 g 0 Tr 0 G 1 w`.
- Underline (bit 4): line of thickness `size/15` at `y = baseline − size/3`; strikethrough (bit 8): thickness
  `size/15` at `baseline + size/3`; drawn by iText `PdfDocument` line-decoration code in the text colour.
- Colours (RGB 0–255, signer side): `black (0,0,0)`, `white (255,255,255)`, `lightGray (192,192,192)`,
  `gray (128,128,128)`, `darkGray (64,64,64)`, `red (255,0,0)`, `pink (255,175,175)` — but lookup is by
  `value.toLowerCase()`, so `lightGray`/`darkGray` are never found and fall back to black (**Bug**, §3.4). Each text
  chunk is preceded by `r g b rg` (components `/255`, printed with up to 5 decimals, e.g. `0.50196 0.50196 0.50196 rg`)
  and followed by `0 g`.

### 8.6 Text layout (non-rotated: `PdfSignatureAppearance.getAppearance` → iText `ColumnText`)

- Box: `dataRect = [MARGIN, MARGIN, w − MARGIN, h − MARGIN]` with `MARGIN = 2` (TOP_SECTION 0 → the whole field).
- Font size = `layer2FontSize` (always set by AutoFirma; **no auto-fit**); leading = font size; alignment left; run
  direction "no bidi". (Only if the size is ≤ 0 does iText auto-fit with `fitText(maxSize = 12)` over the box.)
- Line breaking (greedy, iText `ColumnText`): `\n` forces a break; otherwise break opportunities after characters
  `<= ' '`, `-`, `U+2010`, `U+2002..U+200B` and CJK ranges; a word longer than the line is split at the character
  that overflows; whitespace at the end of a line is dropped. Widths from the standard-14 AFM metrics (or the TTF
  for PDF/A).
- Baselines: line k (1-based) at `y_k = (h − MARGIN) − k·size`, `x = MARGIN`. A line is drawn only if
  `y_k ≥ MARGIN`; remaining text is **silently truncated**. Max lines = `floor((h − 4) / size)`.
  *Observed:* box 200×80, size 12 → baselines 66, 54, 42, 30, 18, 6 (6 lines). Each line is emitted as
  `1 0 0 1 x y Tm` + `(text)Tj` inside one `BT … ET`.
- With a rubric: the image is drawn first (§8.6.1), text after (on top).

#### 8.6.1 Rubric image placement (non-rotated)

`imageScale = -1` → `s = min(w / imgW, h / imgH)` (image pixel dimensions = iText Jpeg width/height, i.e. pixels at
72 dpi); drawn size `iw = imgW·s`, `ih = imgH·s`; offset `x = (w − iw)/2`, `y = (h − ih)/2`; content
`q iw 0 0 ih x y cm /img0 Do Q` (*observed* `q 170.88 0 0 80 14.56 0 cm /img0 Do Q`). Aspect ratio preserved,
centred, letter-boxed.

Image normalisation (when `afirma-ui-utils` present, always in the app): decode with Java ImageIO (JPEG, PNG, GIF,
BMP, WBMP), if it has an alpha channel draw it onto an opaque `TYPE_INT_RGB` canvas pre-filled with the Graphics2D
default colour (**white**) — transparent pixels become white —, re-encode as JPEG with ImageIO defaults (quality
0.75, baseline, JFIF), then embed as `/DCTDecode` image (`/ColorSpace /DeviceRGB` or `/DeviceGray`/`/DeviceCMYK`
from the JPEG). Even JPEG inputs are re-encoded.

### 8.7 Rotated signatures (`signatureRotation ≠ 0`, `buildRotatedSignatureImage`)

```
w, h   = field width, height
r      = degrees mod 360 (made non-negative)
cw, ch = (r in {0,180}) ? (w, h) : (h, w)            # unrotated canvas template "Xf1"
if rubric:
    s  = (r in {90,270}) ? min(h/imgW, w/imgH) : min(w/imgW, h/imgH)
    iw = imgW·s;  ih = imgH·s
    draw image size iw×ih at ((cw − iw)/2, (ch − ih)/2)   # centred in the canvas, aspect preserved
if layer2Text != null:
    canvas.setFontAndSize(font, size)                     # emits "/F1 size Tf" OUTSIDE BT (quirk, observed)
    printText(canvas, text, font, rect = [2, 2, cw − 2, ch − 2])
        # auto-fit: size = fitText(font, text, rect, maxSize = configured size) — §below
        # then ColumnText with leading = fitted size, left aligned (same breaking rules as §8.6)
img = Image(canvas) with rotation r (CCW)
outer "Xf2" = template w×h whose content draws img rotated: "q <cos sin -sin cos tx ty> cm /Xf1 Do Q"
n2 = Xf2 drawn with imageScale 0 (i.e. stretched to w×h = identity here): "q 1 0 0 1 0 0 cm /Xf2 Do Q"
layer2Text of the appearance set to "" (the text lives in Xf1)
```
(The Java variable names for the 90/270 offsets are swapped — `x = (w − ih)/2`, `y = (h − iw)/2`,
`addImage(img, iw,0,0,ih, y, x)` — which yields exactly the centring above.) *Observed* output for 90° on a 200×80
field: `Xf1` BBox `[0 0 80 200]` with the wrapped text at size 12, `Xf2` content `q 0 1 -1 0 200 0 cm /Xf1 Do Q`
(counter-clockwise rotation), n2 content `q 1 0 0 1 0 0 cm /Xf2 Do Q`.

`fitText(font, text, rect, maxSize)`: if text fits at `maxSize` → maxSize; else binary search `min=0, max=maxSize`,
`size=(min+max)/2`, if fits {if `max − min < 0.1·size` return size; `min = size`} else `max = size`, at most 50
iterations, return last size.

### 8.8 Multi-page visible signatures

One appearance, one widget, referenced on every selected page (§5.5). The rectangle is clipped only against the first
page; on smaller later pages it may lie partially outside. Pages where `LLX ≥ width` or `LLY ≥ height` are dropped
from the list.

### 8.9 Coordinates and page rotation

`signaturePositionOnPage*` are interpreted on the page **as displayed** (iText `getPageSizeWithRotation`, which swaps
width/height for 90/270). The widget `/Rect` is converted to unrotated space (§5.5) and the appearance gets a
compensating CTM (§5.6), so the box appears where the user drew it.

### 8.10 Existing signature fields

Detection for the UI: `PdfUtil.getPdfEmptySignatureFields(pdf)` = iText `AcroFields.getBlankSignatureNames()` (fields
with `/FT /Sig` that are not in `getSignatureNames()`), each mapped to `SignatureField(page, round(llx), round(lly),
round(urx), round(ury), name)` from `getFieldPositions` (first widget; rotation-mapped). Fields without a `/Rect` are
skipped. PDF read errors (incl. encrypted) → empty list.

---

## 9. Existing signatures, certified, encrypted, PDF/A, XFA

### 9.1 What counts as a signature

iText `AcroFields.getSignatureNames()`: every terminal field whose merged dictionary has `/FT /Sig` and a `/V`
dictionary containing a `/Contents` **string** and a `/ByteRange` array with ≥ 2 entries. "Revision" of each =
1-based rank when sorted by covered length (`last two ByteRange numbers summed`); `totalRevisions` = count, +1 if the
largest covered length ≠ file length (i.e. there are unsigned changes after the last signature). Document timestamps
are included here (but excluded from `getSignersStructure`).

### 9.2 Unregistered signatures (`PdfUtil.pdfHasUnregisteredSignatures`)

Scan **every object number** `0 … xrefSize−1` (including objects not reachable from the AcroForm); for each
dictionary with `/Type /Sig` whose `/SubFilter` is missing or not in {`/ETSI.RFC3161`, `/adbe.pkcs7.detached`,
`/ETSI.CAdES.detached`, `/adbe.pkcs7.sha1`} → "unregistered" (e.g. `adbe.x509.rsa_sha1`). (The `/Cert` is decoded
only for logging.) Effect: `PdfHasUnregisteredSignaturesException` unless `allowCosigningUnregisteredSignatures=true`
(§3.5). Message key `signingPdfWithUnregisteredSigns`.

### 9.3 Certified PDFs (`PdfUtil.checkPdfCertification`)

Input certification level = catalog `/Perms /DocMDP /Reference[0] /TransformParams /P` (0 if any step missing).
Only **P = 1** blocks (§3.5). Level 2/3 inputs are signed without warning (the new approval signature is allowed by
DocMDP 2/3 rules only if it is a form fill/annotation-level change, which iText's incremental update satisfies).
Also run in the document-timestamp path.

### 9.4 Encrypted / password-protected PDFs

`PdfUtil.getPdfReader(pdf, params, headless)`:
```
if ownerPassword:  PdfReader(pdf, ownerPassword.getBytes())     # platform charset
elif userPassword: PdfReader(pdf, userPassword.getBytes())
else:              PdfReader(pdf)
BadPasswordException -> (password given) BadPdfPasswordException("Se ha indicado una contrasena incorrecta para el PDF")
                        (none given)     PdfIsPasswordProtectedException("El PDF esta protegido por contrasena para lectura")
IOException          -> InvalidPdfException (code 510005 "La firma requiere que los datos sean un documento PDF")
```
Supported decryption: standard security handler R2–R4 (RC4 40/128, AES-128) and R5/R6 (AES-256, patched lib), and
public-key handler (not usable here). Signing requires **owner access**: iText's stamper throws
`BadPasswordException("PdfReader not opened with owner password")` when opened with only the user password
(or with no password when the user password is empty but the owner password is not) → mapped as above (§4 step 10).
Recovery protocol: the exceptions are `RuntimePasswordNeededException`s; `configure(params, pwd)` sets
`ownerPassword = pwd` and **removes** `userPassword`, and the caller retries (§12.7).

### 9.5 PDF/A

- PDF/A-1 (`<pdfaid:part>1</pdfaid:part>`): no full compression; embedded TrueType fonts for the appearance (§8.5).
  Nothing else is enforced (e.g. JPEG rubric is fine, no transparency since images are flattened).
- Any PDF/A part, unsigned: XMP signature history added (§5.10).
- PDF/A-2/3: compression allowed (object streams are permitted from PDF/A-2).

### 9.6 XFA, portfolios, attachments

No special handling. XFA streams are preserved (iText only rewrites XFA if changed, never in signing). Embedded files
and portfolios are not signed individually (documented limitation). AutoFirma prints nothing special.

---

## 10. Validation (`afirma-crypto-validation`) and shadow-attack detection

### 10.1 `ValidatePdfSignature.validate(pdf, params) -> List<SignValidity>`

`validate(pdf)` = `validate(pdf, checkCertificates=true)` = `validate(pdf, {checkCertificates: "true"})` (a
`RuntimeConfigNeededException` is wrapped into `IOException`). `setRelaxed(bool)` (default false) controls whether
"ask the user" situations throw.

Algorithm:
1. Open reader (`PdfUtil.getPdfReader`, passwords from params), `names = getSignatureNames()`; zero names or any
   exception → return `[KO, NO_SIGN]` (error code `INCOMPATIBLE_SIGNATURE`).
2. **Form modification check** — if `allowModifiedForm` is not `true` and `totalRevisions > 1`:
   `errors = DataAnalizerUtil.checkPDFForm(reader)` (§10.2). Non-empty → `e = PdfFormModifiedException("Se han
   detectado cambios en un formulario posteriores a la primera firma")`; if relaxed: `e.denied = (allowModifiedForm
   is set)`; **throw e**. Else add `[KO, MODIFIED_FORM, e]`, `formModified = true`.
3. **PSA check** — skipped if `allowModifiedForm=true` or `formModified` or `allowShadowAttack=true`. Else, if
   `totalRevisions > 1` and `revision(names[0]) < totalRevisions` (i.e. there are changes after the most recent
   signature — `names[0]` assumed newest, §1.3): `v = checkPdfShadowAttack(pdf, extractRevision(names[0]),
   pagesToCheck = param or "10")` (§10.3). If `v != null`: if relaxed and `v` is PENDING and `allowShadowAttack` is
   **unset** → throw `SuspectedPSAException("PDF sospechoso de haber sufrido PDF Shadow Attack")`; if PENDING →
   convert to `KO` (same error); add `v`.
4. `profile = SignatureFormatDetectorPadesCades.resolvePDFFormat(pdf)` (§10.4).
5. For each name: `validateSign(name, af, profile, checkCertificates)` →
   - `pk = verifySignature(name)`; `pk.getStrictHashAlgorithm() == null` (digest OID not a pure hash OID) →
     `[KO, ALGORITHM_NOT_SUPPORTED]`;
   - unless SubFilter is `ETSI.RFC3161`: `pk.verify()` false → `[KO, NO_MATCH_DATA]`; exception →
     `[KO, CORRUPTED_SIGN, e]`. `verify()` = (messageDigest attr == H(range)) ∧ signature over signed attributes valid
     (or over the digest if no signed attributes);
   - if `checkCertificates`: `signingCert.checkValidity()` (now) → `[KO, CERTIFICATE_EXPIRED]` /
     `[KO, CERTIFICATE_NOT_VALID_YET]`;
   - if profile ∉ {`PAdES-Basic`, `No reconocido`, `PAdES-BES`, `PAdES B-Level`, `PAdES B-B-Level`, `PAdES-EPES`} →
     `[UNKNOWN, SIGN_PROFILE_NOT_CHECKED]` (long-term profiles are not validated);
   - none → `[OK]`.
   Merge: for each returned validity not already in the list (identity comparison — `SignValidity` has no
   `equals`, so effectively always added): UNKNOWN → insert at index 0; non-OK → append; OK → dropped.
6. Certified level-1 documents (only if the list is still empty): `certRevision` = revision of a signature whose
   dictionary has `/Reference[0] /TransformMethod`; every signature with `revision > certRevision` →
   `[KO, CERTIFIED_SIGN_REVISION]` (error code `212007`).
7. `checkValidityKOPriority`: KO entries moved to the front (each inserted at index 0, so the **last** KO ends first).
8. `checkLongStandingValiditySign`: if the only KOs are `CERTIFICATE_EXPIRED` and there is an UNKNOWN
   `SIGN_PROFILE_NOT_CHECKED`, swap that UNKNOWN to position 0.
9. Empty → `[OK]`. Callers use element 0 as the verdict.

### 10.2 Form-change check (`DataAnalizerUtil.checkPDFForm`)

- Current values: `getFieldValues(reader)`: for each `PRAcroForm` field with info: if `/FT` ≠ `/Sig` →
  `name → /V object` (may be null). Plus, for every page `/Annots` entry that is a `/Type/Annot /Subtype/Widget`
  without `/FT /Sig`: name = `/T` string (or `P<page>A<index>`), added if not already present.
- Original values: same function on the revision covered by `names[last]` (assumed **oldest** signature).
- For each original field: compare `toString()` of the PDF objects (iText string form) with the current one; differences
  (including removal) recorded; fields present only in the current version are **not** reported (except when the
  original value was null and the current one is non-null). Non-empty → modified.

### 10.3 Shadow-attack check (`DataAnalizerUtil.checkPdfShadowAttack`)

Uses **Apache PDFBox** (`PDDocument.load`, `PDFRenderer`):
```
pages = "all" ? currentDoc.pageCount : parseInt(pagesToCheck)      # NumberFormatException etc. -> swallowed, returns null
for i in 0 .. pages-1:                                              # IndexOutOfBounds if fewer pages -> swallowed (returns null)
    if overlapping(currentDoc.page(i).annotations):
        return PENDING_CONFIRM_BY_USER, OVERLAPPING_SIGNATURE, SuspectedPSAException("El documento incluye firmas visibles solapadas")
    a = render(currentDoc, i, dpi=40, GRAY); b = render(signedRevision, i, dpi=40, GRAY)
    if a.size != b.size or any pixel differs (sum |ΔR|+|ΔG|+|ΔB| > 0):
        return PENDING_CONFIRM_BY_USER, MODIFIED_DOCUMENT, SuspectedPSAException("El documento ha cambiado de aspecto")
return null           # also on any exception ("Error al cargar el fichero, se salta al siguiente")
```
`overlapping(annots)` (buggy, replicate): for `i` in `0..n-2`, if `annots[i]` is a widget with non-zero rect:
`checkIsOverlapping(rect_i, annots, ++i)` — note `i` is incremented (skips the next element as a start) — which
returns **false** as soon as the *first* following annotation does not intersect (strict separation test on min/max
X/Y) and **true** only if *all* following annotations (any type) intersect it. Pixel exactness means any new visible
appearance, stamp or content change after the newest signature flags the document.

### 10.4 PAdES profile detection (`resolvePDFFormat`)

Uses the signature with the highest revision whose SubFilter ≠ `ETSI.RFC3161` and `/Type` absent or `/Sig`:
- **B-Level**: SubFilter `ETSI.CAdES.detached`, `/M` present, and a SignerInfo has `signingCertificate` (v1).
- **B-B-Level**: same with `signingCertificateV2` (AutoFirma default ⇒ `PAdES B-B-Level`).
- For B/B-B: `LTA` if (signature TS count > 1 or DocTimeStamp count > 1) and a `/DSS` exists in the catalog or in any
  extracted revision; else `LT` if `T` and DSS; else `T` if exactly one signature TS and no DocTimeStamp, or no
  signature TS and exactly one DocTimeStamp (requires certificates present in the CMS).
- Otherwise: `PAdES-LTV` if catalog `/DSS` or any DocTimeStamp; else `PAdES-EPES` (CAdES subfilter + sigPolicyId in
  any signer/countersigner), `PAdES-BES` (CAdES subfilter, no policy in first signer), `PAdES-Basic`
  (`adbe.pkcs7.detached`/`adbe.pkcs7.sha1`), `PDF` (other subfilter). Errors → `No reconocido`.
Constants: `"PAdES B-Level"`, `"PAdES B-B-Level"`, `"PAdES T-Level"`, `"PAdES LT-Level"`, `"PAdES LTA-Level"`,
`"PAdES-LTV"`, `"PAdES-EPES"`, `"PAdES-BES"`, `"PAdES-Basic"`, `"PDF"`, `"No reconocido"`.

### 10.5 Result types and messages

`SIGN_DETAIL_TYPE`: `OK, KO, UNKNOWN, PENDING_CONFIRM_BY_USER, GENERATED`.
`VALIDITY_ERROR` (with `es_ES` message `SignValidationMessage.N`): `NO_DATA`(4), `CORRUPTED_SIGN`(5 "la información
contenida en la firma no es consistente…"), `NO_MATCH_DATA`(6 "la firma no se corresponde con los datos firmados"),
`NO_SIGN`(7), `CERTIFICATE_PROBLEM`(8), `CERTIFICATE_EXPIRED`(9 "existe un certificado de firma caducado"),
`CERTIFICATE_NOT_VALID_YET`(10), `CANT_VALIDATE_CERT`(11), `ALGORITHM_NOT_SUPPORTED`(12), `CA_NOT_SUPPORTED`(13),
`CRL_PROBLEM`(14), `PDF_UNKOWN_VALIDITY`(15), `OOXML_UNKOWN_VALIDITY`(16), `ODF_UNKOWN_VALIDITY`(17),
`UNKOWN_ERROR`(18), `UNKOWN_SIGNATURE_FORMAT`(19), `MODIFIED_DOCUMENT`(20 "el documento PDF es sospechoso de haberse
modificado tras la firma"), `OVERLAPPING_SIGNATURE`(21 "las firmas del documento se solapan pudiendo ocultar
información"), `MODIFIED_FORM`(22 "un formulario del documento fue modificado tras la firma"),
`SUSPECTED_SIGNATURE`(23), `SIGN_PROFILE_NOT_CHECKED`(24 "la firma contiene atributos longevos que Autofirma no puede
validar…"), `CANT_VALIDATE_EXTERNALLY_DETACHED`(25), `BAD_BUILD_SIGN`(26), `CERTIFIED_SIGN_REVISION`(27 "El documento
certificado no permitía nuevas firmas"). Type texts: 0 "Firma válida", 1 "Validación incompleta", 2 "Validez a
confirmar por el usuario", 3 "Firma no válida".

### 10.6 Where the checks run and with which parameters

| Caller | Params | Relaxed | Consequence |
|---|---|---|---|
| Desktop GUI, when a signed PDF is loaded (`SignPanel.setValidationInfo`) | `checkCertificates=true`, `pagesToCheckShadowAttack=all`, `allowShadowAttack=true` **unless** preference `allowShadowAttack` (which means "check PSA", default `false`) is true | no | Result shown; element 0 KO ⇒ signing refused ("No se permite agregar nuevas firmas a documentos con firmas no válidas.") unless preference `allowInvalidSignatures=true`. PSA in non-relaxed mode becomes KO. |
| Protocol sign / sign-and-save with `checkSignatures=true` | request params; if `allowShadowAttack` not `true` and `pagesToCheckShadowAttack` unset → set to `10` | yes | `RuntimeConfigNeededException` → (headless → abort) confirm dialog (title `SignPanelSignTask.4`), Yes → set its param (`allowShadowAttack`/`allowModifiedForm`) to `true` and re-validate; KO (other than NO_SIGN on a plain sign) → error. |
| Triphase server presign with `checkSignatures=true` (only if the PDF is already signed) | request params after `configurePdfShadowAttackParameters`: if `allowShadowAttack` ≠ true: `pages = param ("all" → MAX, invalid → 10, default 10)`, `pages = min(pages, server maxPagesToCheckShadowAttack (config, default 10, "all" = MAX))`; `pages <= 0` → `allowShadowAttack=true`; else `pagesToCheckShadowAttack=pages` | yes | `RuntimeConfigNeededException` → response `ERR-21:<requestorText>:…` (client re-raises it, §11.4); element 0 KO → `InvalidSignatureException`. |
| Server batch (`TriPhaseHelper`) | same, but additionally sets `allowShadowAttack=false` explicitly when not true | yes | Because the param is now *set*, a PSA suspicion is "denied" → KO instead of asking. |

---

## 11. Three-phase (trifásica) PAdES

### 11.1 Split

| Phase | Where | What |
|---|---|---|
| Pre-sign | server (`PAdESTriPhasePreProcessor.preProcessPreSign`) | Loads the document by id, checks `%PDF-` (else `InvalidPdfException`), optional validation (§10.6), `signTime = now` (server clock), `PAdESTriPhaseSigner.preSign(getDigestAlgorithmName(algo), pdf, certChain, signTime, extraParams, secureMode=true)` → `PdfSignResult(fileID, signedAttributesDER, signTime, params)`. **No document timestamp** step in triphase. |
| Sign | client | PKCS#1 over the signed attributes |
| Post-sign | server (`preProcessPostSign`) | Rebuilds PdfSignResult from the session, `PAdESTriPhaseSigner.postSign(...)` with the original document → signed PDF, stored by the server's document manager. |

### 11.2 Session data (`TriphaseData`, XML format in `07-core.md` §3.4)

One `TriSign` (id = `SignatureId` param or random UUID) with properties:

| Key | Value |
|---|---|
| `PRE` | Base64(DER `SET OF Attribute` — the CAdES signed attributes, §6.3) |
| `NEED_PRE` | `true` (PRE must be sent back) |
| `TIME` | `signTime.getTimeInMillis()` decimal |
| `PID` | Base64 of the file-ID **string** bytes, e.g. Base64(`[<hex32><hex32>]`) |
| `HMAC` | (added by `SignatureService` only when the server config has `verification.key`) Base64(HmacSHA256(key = UTF-8(verification.key), data = UTF-8(PRE Base64 string) ‖ UTF-8(verification.key) ‖ signer cert DER)); verified at post-sign (mismatch → `ERR-` "CHECKING_CSV_ERROR") |
| `PK1` | (added by client) Base64 PKCS#1 signature |

### 11.3 Client (`AOPDFTriPhaseSigner` / `PDFTriPhaseSignerUtil`)

1. `documentId = Base64URL(data)` (`Base64.encode(data, urlSafe=true)`).
2. Pre-sign request: POST to `serverUrl` with body (UrlHttpManager converts the query string)
   `op=pre&cop=sign&format=pades&algo=<algorithm>&cert=<certs>&doc=<documentId>[&params=<properties2Base64(extraParams)>]`.
   `cert` = Base64URL(DER) of each chain cert joined with `,` (only `chain[0]` if
   `includeOnlySignningCertificate=true`).
3. Response: ≤ 8 bytes → `AOException(MALFORMED_PRESIGN_RESPONSE)`; starts with `ERR-` → §11.4; else
   `TriphaseData.parser(Base64URL-decode(response))`.
4. For each TriSign: `PK1 = Base64(AOPkcs1Signer.sign(Base64-decode(PRE), composeSignatureAlgorithmName(algo,
   key.getAlgorithm()), key, chain, extraParams))`; delete `PRE` unless `NEED_PRE=true` (PAdES keeps it).
5. Post-sign request: `op=post&cop=sign&format=pades&algo=…&cert=…&doc=…&session=<Base64URL(TriphaseData XML)>
   [&params=…]`.
6. Response must (after trim) start with `OK`; result = Base64URL-decode of the text after `OK NEWID=` = **new document
   id**, not the PDF. HTTP 400 → `INVALID_PARAMS_TO_PRESIGN/POSTSIGN`, other 4xx → communication error, others →
   `PRESIGN/POSTSIGN_HTTP_ERROR`; socket timeout → `*_SERVICE_TIMEOUT`.

### 11.4 Error mapping (`buildInternalException`)

Messages `ERR-21:<code>:<text>` (configuration needed) map to: `signingCertifiedPdf` → `PdfIsCertifiedException`,
`signingPdfWithUnregisteredSigns` → `PdfHasUnregisteredSignaturesException`, `signingModifiedPdfForm` →
`PdfFormModifiedException`, `pdfShadowAttackSuspect` → `SuspectedPSAException`, `pdfpasswordprotected` /
`pdfbadpassword` → `BadPdfPasswordException` if the request carried `ownerPassword`/`userPassword`, else
`PdfIsPasswordProtectedException`. Other `ERR-nn:` messages → `AOTriphaseException.parsePresign/PostsignException(code,
message, exceptionClassName)` (format `ERR-nn:message[:className[:internalMessage]]`). The UI then handles them like
local exceptions (§12.7) and retries with the corresponding param.

### 11.5 Post-sign reconstruction (determinism contract)

`postSign` calls `getSessionData(pdf, chain, signTime=TIME, params)` again: the server must produce **exactly** the
same bytes as during pre-sign (same objects, offsets, compression, XMP, `/M`, Info `/ModDate`, appearance text incl.
date tokens formatted in the *server's* locale/time zone…), except the random `/ID`. Then it fills `/Contents`, and
replaces every occurrence of the new file-ID string with `PID` (ISO-8859-1 string replacement over the whole file),
restoring the exact bytes that were hashed. Any nondeterminism (e.g. hash-map iteration order, current time, random
IDs elsewhere) breaks the signature. `PdfSignResult` Java serialization (`writeObject`) writes an XML with a
mismatched `</pdfIf>` tag (**Bug**, never round-trips); it is not used by the protocol.

### 11.6 Other triphase notes

- `doNotUseCertChainOnPostSign` exists for servers that should not embed signer identity in the PDF layer.
- Visible-signature parameters travel in `params`; the rubric image travels Base64 inside them (server secure mode on
  → no paths).
- Batch signing uses the same pre-processor (`SingleSignConstants.SignFormat.PADES` = `PAdES`), with the PSA
  parameter rules of §10.6.

---

## 12. Desktop UI (`afirma-simple`)

### 12.1 Preferences (PAdES tab, `PreferencesPanelPades`; storage in `06` §4)

| Pref key | Default | UI control | Effect |
|---|---|---|---|
| `padesSignReason` | `""` | text "Motivo" | `signReason` if non-blank |
| `padesSignProductionCity` | `""` | text | `signatureProductionCity` if non-blank |
| `padesSignerContact` | `""` | text | `signerContact` if non-blank |
| `padesBasicFormat` | `ETSI.CAdES.detached` | combo `PAdES-BES` (`ETSI.CAdES.detached`) / `PAdES Básico` (`adbe.pkcs7.detached`) | `signatureSubFilter` if non-blank. Forced to PAdES-BES and disabled when a policy is configured. |
| `padesPolicyIdentifier`, `padesPolicyIdentifierHash`, `padesPolicyIdentifierHashAlgorithm`, `padesPolicyQualifier` | empty | policy dialog (none / AGE 1.9 preset / custom) | `policyIdentifier` (+ hash, algorithm, qualifier only if the identifier is set) |
| `padesVisibleSignature` | `false` | "Realizar por defecto firmas visibles PDF" | initial state of the sign panel checkbox "Hacer la firma visible dentro del PDF" (`SignPanel.44`) |
| `padesVisibleStamp` | `false` | "Aplicar marca visible a documentos PDF" | initial state of "Insertar una marca visible dentro del PDF" (`SignPanel.120`); disabled for co-sign ("No se pueden aplicar marcas visibles a documentos ya firmados") |
| `padesObfuscateCertInfo` | `true` | "Ofuscar identificadores de usuario de los certificados de las firmas visibles" | `obfuscateCertText` (always written, `true`/`false`) |
| `allowShadowAttack` (**means "check PSA"**) | `false` | "Comprobar PDF Shadow Attack" (warning dialog "Al activar esta opción, el proceso de validación para PDF puede retrasarse.") | §10.6 |
| `allowCertifiedPDF` | `false` | "Permitir generar PDF certificado." | shows the "Generar firma PDF certificado" checkbox + level combo in the sign panel |
| `padesCertificationLevel` | `0` | combo Sin certificar / Certificada de autor / … para formularios / común | default `certificationLevel` |
| `pdfLayer2Text` | `Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$` | appearance editor | |
| `pdfLayer2FontFamily` | `0` | editor | |
| `pdfLayer2FontSize` | `12` | editor | |
| `pdfLayer2FontStyle` | `0` | editor | |
| `pdfLayer2FontColor` | `black` | editor | |
| `pdfSignatureRotation` | `0` | editor | |
| `pdfSignatureImage` | `""` | editor (file **path**) | |
| `defaultSignatureFormatPdf` | `PAdES` | general tab | format for PDF inputs |
| `allowInvalidSignatures` | `false` | general tab | allow signing when validation result is KO |

`ExtraParamsHelper.loadPAdESExtraParams` builds the params listed above (policy, reason, city, contact, sub-filter,
`obfuscateCertText`). System properties are merged into every operation's params (`-Dkey=value`).

### 12.2 Sign-panel flow (`SignPanel.sign` → `VisiblePdfSignatureManager`)

1. If the single loaded file has validity KO and `allowInvalidSignatures` is false → error, stop.
2. If any operation is a PDF signature: `visibleSignature`, `visibleStamp`, `certificationLevel` from the file panel
   checkboxes (single file) — or, for multi-file, `visibleSignature = padesVisibleSignature`, `visibleStamp = false`,
   and certification level from `padesCertificationLevel` **if `padesVisibleSignature` is true** (**Bug:** wrong
   preference tested; should be `allowCertifiedPDF`). Level ≠ `0` → `certificationLevel` added to every operation.
3. Configs are cloned (so cancelling leaves no visible-signature params) and
   `VisiblePdfSignatureManager.getVisibleSignatureParams(configs, …)`:
   - Load the first PDF. `emptyFields = PdfUtil.getPdfEmptySignatureFields(data)`.
   - If there are empty fields → option dialog "Se ha detectado un campo de firma vacío en el documento. Seleccione el
     campo en el que desea insertar la firma o si desea agregarla en un nuevo campo." with a combo of field names and
     buttons `Usar campo seleccionado` / `Crear campo nuevo` / `Cancelar firma`:
     - Use → `signatureField=<name>` on every config; if stamp requested → stamp dialog only (`signatureVisible=false`);
       else sign.
     - Create → as if there were no fields (below).
     - Cancel → `AOCancelledOperationException` → whole operation cancelled.
   - Else if visible or stamp → `SignPdfDialog` (§12.3), `customAppearance = true` always in the GUI.
   - Else sign directly.
4. Dialog result → `propertiesCreated(props)`: non-empty props are added to every **PDF** operation (`AOPDFSigner`);
   then the sign task starts. **Cancelling the dialog (button, Esc, window close) yields empty props and signing
   continues with an invisible signature.** Exceptions while preparing the dialog → logged, invisible signature.

### 12.3 `SignPdfDialog`

- Title `SignPdfDialog.3`; toolkit-modal; preferred size 500 × min(800, 0.9·screenH) (stamp: +60).
- Background thread renders pages: `Pdf2ImagesConverter.pdf2ImagesUsefulSections(pdf, password, 0)` with **PDFBox**
  at **75 dpi RGB**, only "useful" pages: index < 4, ≥ N−4, or |i − current| ≤ 4; others `null` and rendered lazily
  (`updateUsefulSections` on navigation). PDFBox `InvalidPasswordException` → password prompt (`pdfpasswordprotected`,
  then `pdfbadpassword` on retry); cancel → error. Page sizes from iText `getPageSizeWithRotation` rounded to ints. The
  password entered becomes `ownerPassword` in the produced params.
- `OutOfMemoryError` → error `SignPdfDialog.4`; other load errors `SignPdfDialog.0` → empty params (invisible).
- Panels: visible → `SignPdfUiPanel` (area) → `SignPdfUiPanelPreview` (appearance) → [stamp → `SignPdfUiPanelStamp`]
  → done; stamp only → `SignPdfUiPanelStamp` → done.
- After the area panel, `checkSignatureDimensions`: `dx = |URX − LLX|`, `dy = |URY − LLY|`; reject if `dx < 30` or
  `dy < 45` or `dx·dy < 1350` → error "El área seleccionada para mostrar la firma tiene un tamaño demasiado pequeño."
  (title "Tamaño inválido"); stay on the panel.
- If a preloaded rubric (from preferences) has transparency → warning "No se soporta el uso de imagenes con
  transparencias. La previsualización no refleja el acabado final de la firma."

### 12.4 Area selection (`SignPdfUiPanel` + `PageLabel`)

Layout (dialog title "Propiedades de la firma visible PDF"): group "Posición de firma" with message "Inserte o
seleccione el área de firma visible." (multi-file: "… para todos los documentos."), four numeric fields `X:` / `Y:` /
`Anchura:` / `Altura:` (digits only, max 4 characters), page image (panel 466 × 400) and pagination
`<< < "Página %0 de %1 (escala: %2%)" > >>`; group "Página de firma" with radio buttons `Página actual` (default) /
`Todas las páginas` / `Selección de páginas` + free text + help button (`pgs/VentanaPdfVisible.html`); buttons
`Siguiente` (enabled only with a valid rectangle) / `Cancelar` (order swapped on macOS).

Image scaling (`createPageLabel`), with the rendered page image `W_img × H_img` px and PDF size `Wpt × Hpt`:
```
w, h = W_img, H_img
while w > 466 or h > 400: w = round(w*0.9); h = round(h*0.9)
aspect = w / W_img;  scalePercent = round(100*aspect)
w = round(W_img*aspect); h = round(H_img*aspect)
s = (W_img <= H_img and Wpt <= Hpt) ? Hpt / h : Wpt / w        # "pdfRatio", points per label pixel
```
Mouse: press = start, drag draws a translucent blue rectangle (alpha 0.3) over a white 50 % veil; release with zero
width/height clears; else points clamped to the label, rect `(x, y, w, h)` in label pixels, and the **fields** are set
to `round(min(x,lw)/s)`, `round(min(y,lh)/s)`, `round(w/s)`, `round(h/s)` (**Quirk:** divided by `s`, so the numbers
shown are not points). Any field change recomputes `r = ((int)(X·s), (int)(Y·s), (int)(W·s), (int)(H·s))` (back to
label pixels) and, if `w,h > 0`, the PDF parameters:
```
dim = pageSize(currentPage == 1 ? 1 : currentPage − 1)        # Bug: previous page's size for pages > 1
if r.x > dim.w or r.y > dim.h: no position
if r.x + r.w > dim.w: r.w = dim.w − r.x;  if r.y + r.h > dim.h: r.h = dim.h − r.y
areaH = (r.h + r.y > lh) ? lh − r.y : r.h;  areaW = (r.w + r.x > lw) ? lw − r.x : r.w
LLX = round(r.x·s);  LLY = round((lh − r.y − areaH)·s)
URX = round((r.x + areaW)·s);  URY = round((lh − r.y)·s)
```
OK button → params: `signaturePages` = `all` | the free text (validated by `PdfUtil.checkPagesRangeInputFormat`:
non-empty, only `0-9`, `-`, `,`; not ending in `,`; no `---`, no `,,`; no element ending in `-`, starting with
`--`, or equal to `-`; error "Error en el formato indicado en la selección de páginas…") | current page number; if the
current page is the appended blank page, `,append` is appended (**Bug:** `getPages` only honours `append` as the first
element, so the signature lands on the last page and no page is added); plus the four position keys, plus initial
params (`ownerPassword`).

Navigation: buttons and Left/Right keys; Right/next on the last page of an **unsigned** PDF asks "¿Desea añadir una
página en blanco al final del documento para firmar?" and shows a white page of page-1 size; Esc cancels.

Preview fragment for the next panel: page image resized to `Wpt × Hpt` (bilinear), sub-image
`x = max(0,LLX)`, `y = max(0, Hpt − URY)`, `width = max(URX − 4 − LLX, 1)`, `height = max(URY − LLY, 1)`.

### 12.5 Appearance editor (`SignPdfUiPanelPreview`)

- Preview box 475 × 200: the fragment is shrunk by repeated ×0.9 until it fits; `scale = (int)(origW / newW)`
  (**integer division**). Clicking the preview (or Ctrl+P, or context menu "add image") opens an image chooser
  (`jpg, jpeg, png, gif, bmp`); right-click with an image → "remove image". Drag & drop of one local file supported
  (URLs rejected). Hint text with link to the wiki help page "Help-desktop-visible-pdf".
- Groups "Vista Previa" and "Configuración de firma". Controls: "Imagen de firma:" read-only path field +
  `Examinar` / `Limpiar`; "Texto de la firma:" text area (4×60, word-wrap, Tab moves focus) initialised from
  `pdfLayer2Text`; font combo `Courier`, `Helvetica`, `Times Roman` (preview fonts: installed system fonts with those
  names, else the bundled FreeFont TTFs); size spinner 1–50 (step 1, initial 12); rotation combo `No rotar`,
  `Rotar 90º`, `Rotar 180º`, `Rotar 270º`; toggle buttons **N** (bold, Ctrl+N), *K* (italic, Ctrl+K), S underline
  (Ctrl+S), T strikethrough (Ctrl+T) — underline/strikethrough are mutually exclusive with everything else, bold+italic
  may combine; colour combo Negro, Blanco, Gris claro, Gris, Gris oscuro, Rojo, Rosa; checkbox "Recordar
  configuración" (checked); buttons `Restaurar configuración` (load the *default* preference values) / `Aceptar` /
  `Cancelar`.
- Style index sent: strikethrough → 8, underline → 4, bold+italic → 3, italic → 2, bold → 1, else 0.
- **Preview rendering does not substitute tokens** (the raw `$$…$$` text is drawn). Text drawn with AWT: size
  `max(1, round(size / scale) − 3)`, colour of the combo (**Quirk:** UI RGB for `lightGray` is (128,128,128) and for
  `gray` (192,192,192) — swapped w.r.t. the signer), lines split on `\n` and word-wrapped with `FontMetrics` to the
  image width, baseline `y += fontHeight` from 0, `x = 4`, rotated with `Graphics2D.rotate` (90 → −π/2, 270 → +π/2).
  Rubric drawn scaled-to-fit centred and rotated (by the opposite angle to match the PDF CCW rotation). The preview is
  explicitly "may differ from the final result".
- Aceptar: `layer2Text = text.trim()` (always set, possibly empty); if non-empty also `layer2FontFamily`
  (`0`/`1`/`2`), `layer2FontSize`, `layer2FontStyle`, `layer2FontColor` (`black`…`pink`); `signatureRotation` only if
  ≠ 0; if an image path is set: file bytes read, validated with `ImageIO.read`, `signatureRubricImage =
  Base64(original bytes)` (PNG etc. are converted to JPEG by the signer, §8.6.1); read error → message and stay.
  If "Recordar configuración": save `pdfLayer2Text` (and font family/size/style/color only if the text is non-empty),
  `pdfSignatureRotation` (only if ≠ 0 — so going back to 0 is not remembered), `pdfSignatureImage` = path or removed.
- Esc = cancel.

### 12.6 Stamp panel (`SignPdfUiPanelStamp`) and protocol behaviour

- Title "Propiedades de marca visible", message "Inserte o seleccione el área para la imagen de marca visible.".
  Same page display/selection mechanics (panel 466×410, same coordinate maths) plus checkbox "Incluir imagen en todas
  las páginas." (disables navigation) and `Seleccionar imagen` chooser (`jpg, jpeg, png, gif, bmp`, validated with ImageIO). Aceptar (enabled when image and area exist) →
  `image = Base64(file bytes)`, `imagePage = "0"` (all) or current page, `imagePositionOnPage*` (same formulas).
- Protocol (`ProtocolInvocationLauncherSign`): after `expPolicy` expansion, if the format is one of `Adobe PDF`,
  `Adobe PDF TriPhase`, `PAdES`, `PAdEStri`, `ETSI.CAdES.detached`, `adbe.pkcs7.detached` and `visibleSignature` ∈
  {`want`,`optional`} (ignore case) → `SignPdfDialog` (signature only, `customAppearance = visibleAppearance=custom`).
  Result copied into params: four position keys, `signaturePage` if present else `signaturePages`, and
  `layer2Text`, `layer2FontFamily`, `layer2FontSize`, `signatureRotation`, `layer2FontStyle`, `layer2FontColor`,
  `signatureRubricImage` when present. Cancel with `want` and no area/page params → `VisibleSignatureMandatoryException`
  ("Es obligatorio mostrar la firma en el documento PDF"); with `optional` → invisible. **Bug:**
  `ProtocolInvocationLauncherSignAndSave.updateOptions` copies only `signaturePage` and calls
  `setProperty(key, null)` when the UI produced `signaturePages` → `NullPointerException` in the listener (position
  keys already copied, appearance keys lost). The dialog is shown even if position params were already supplied.

### 12.7 Exception → user interaction (GUI `SignPanelSignTask`, protocol launchers)

All PAdES "needs user input" exceptions are `RuntimeConfigNeededException` with `(requestType, requestorText, param)`:

| Exception | requestorText (message key) | Type | Param set on "Yes" / password | Error code |
|---|---|---|---|---|
| `PdfIsCertifiedException` | `signingCertifiedPdf` — "El PDF que desea firmar está certificado y no admite nuevas firmas. Agregar nuevas firmas invalidará la firma anterior.\n¿Desea continuar?" | CONFIRM | `allowSigningCertifiedPdfs=true` | `212007` |
| `PdfHasUnregisteredSignaturesException` | `signingPdfWithUnregisteredSigns` — "…contiene firmas previas en un formato antiguo. Agregar nuevas firmas podría invalidar las ya existentes.\n¿Desea continuar?" | CONFIRM | `allowCosigningUnregisteredSignatures=true` | `212003` |
| `PdfFormModifiedException` | `signingModifiedPdfForm` | CONFIRM | `allowModifiedForm=true` | `212006` |
| `SuspectedPSAException` | `pdfShadowAttackSuspect` — "El PDF es sospechoso de haber sido modificado tras la última firma. ¿Desea continuar?" | CONFIRM | `allowShadowAttack=true` | `212008` |
| `PdfIsPasswordProtectedException` | `pdfpasswordprotected` — "El PDF está protegido por contraseña. Introduzca de la contraseña del PDF." | PASSWORD | `ownerPassword=pwd`, remove `userPassword` | `212005` |
| `BadPdfPasswordException` | `pdfbadpassword` — "La contraseña introducida es incorrecta. Introduzca de la contraseña del PDF." | PASSWORD | same | `212004` |

`isDenied()` (set when the caller already gave a non-`true` answer) means "do not ask, fail". GUI: only for a single
file; confirm dialog title "Confirmación requerida" (`SignPanel.153`); Yes → param set, `needRelaunch` → the signature
is retried; No/cancel → stop. Multi-file → `headless=true` is added and the file is skipped on such errors. Other
types → "No se pudo completar la firma: %0". The PSA/form exceptions only arise from validation (relaxed callers),
never from `AOPDFSigner`.

---

## 13. Error codes (PAdES)

| Code | Constant | Meaning / thrown by |
|---|---|---|
| `212001` | `UNKWNON_PADES_SIGNING_ERROR` | (unused) |
| `212002` | `INTERNAL_PADES_SIGNING_ERROR` | stamper/creation errors, CMS too big, close errors, TSA composition |
| `212003` | `SIGNING_PDF_WITH_UNREGISTER_SIGNATURES` | `PdfHasUnregisteredSignaturesException` |
| `212004` | `SIGNING_PDF_WITH_BAD_PASSWORD` | `BadPdfPasswordException` |
| `212005` | `SIGNING_PDF_WITHOUT_PASSWORD` | `PdfIsPasswordProtectedException` |
| `212006` | `SIGNING_PDF_WITH_MODIFIED_FORM` | `PdfFormModifiedException` |
| `212007` | `SIGNING_PDF_WITH_CERTIFIED_SIGN` | `PdfIsCertifiedException`; validation `CERTIFIED_SIGN_REVISION` |
| `212008` | `SIGNING_PDF_WITH_SUSPICION_OF_PSA` | `SuspectedPSAException` |
| `300002` | `ITEXT_VERSION_NOT_SUPPORTED` | `InvalidITextException` (wrong iText on classpath) |
| `510005` | `PDF_DOCUMENT_NEEDED` | `InvalidPdfException` |
| `610301` | `INVALID_SIGNATURE_POSITION` | `InvalidSignaturePositionException` |
| `610302` | `INVALID_SIGNATURE_PAGE` | `IncorrectPageException` (normally caught) |

---

## 14. Consolidated quirks / bugs (decide: replicate or fix)

1. Default sub-filter is `ETSI.CAdES.detached` despite Javadoc (§3.1). Replicate.
2. Output header always `%PDF-1.7` on first signature (full rewrite); catalog `/Version` and `/Extensions` never
   written; `pdfVersion=4` + compression → 1.4 header with xref streams (§5.2).
3. First signature rewrites the whole file (earlier revisions lost); co-signing is incremental (§5.1).
4. Trailer `/ID` fully regenerated on every signature (first element changes too, unless encrypted) (§5.2).
5. Timestamps broken by reflection bug (§7.4); document TS placed *before* the signature (§7.3).
6. Multi-page signature = one widget referenced N times, `/Fields` contains duplicates (§5.5).
7. Existing field + rubric (no text) → blank appearance; rotation/rubric ignored for fields (§8.1).
8. `layer2FontFamily` 3/4 render as Courier; bold/italic simulated (§8.5).
9. Non-rotated text never shrinks (truncated); rotated text auto-shrinks (§8.6/§8.7).
10. Obfuscation counts digits in the whole string and does not reset the digit counter on separators (§8.4).
11. `$$PSEUDONYM$$` left literal when absent; `$$SIGNDATE` without closing `$$` throws; dates locale/TZ dependent (§8.2).
12. Page `0` means page 1; `append` only as first element; UI `,append` therefore ignored (§3.3, §12.4).
13. `isSign` uses `System.getProperties()` for the unregistered-signature allowance (§1.4).
14. Signature-name order = Java HashMap order (newest first for `SignatureN`, N ≤ 10); validation relies on it (§1.3, §10.1).
15. XMP history date fix-up by global string replace (§5.10).
16. Shadow-attack overlap test logic is inverted/partial; checks only the first N pages; any exception ⇒ "not suspicious" (§10.3).
17. UI coordinate fields show `px/s` instead of points; previous-page size used for clipping on pages > 1 (§12.4).
18. UI colour swap lightGray/gray between preview and signer (§12.5); signer renders `lightGray`/`darkGray` as black (§3.4).
19. Multi-file GUI reads certification level depending on `padesVisibleSignature` (§12.2).
20. `ProtocolInvocationLauncherSignAndSave` NPE with `signaturePages` (§12.6).
21. `getData` returns the signed PDF unchanged (§1.2).
22. `PdfSignResult` serialization writes `</pdfIf>` (§11.5).
23. `configureRespectfulProperties` may copy `ETSI.RFC3161` (§1.2).
24. `signReason` silently dropped when a policy is set (§1.2).

---

## 15. Parity checklist

| # | Feature | Java class(es) | Notes for the Rust port |
|---|---|---|---|
| 1 | Format registry `Adobe PDF`/`PAdES`/`…TriPhase`/`PAdEStri` | `AOSignerFactory` | §1.1 |
| 2 | `sign` / `cosign` / `countersign` (unsupported) | `AOPDFSigner` | §1.2, pipeline §2 |
| 3 | `checkParams` normalisations (MD reject, baseline, CTI, reason vs policy) | `AOPDFSigner.checkParams` | §1.2 |
| 4 | `getSignersStructure`, `isSign`, `isValidDataFile`, `getData`, `getSignInfo`, `getSignedName` | `AOPDFSigner` | §1.2–§1.4; order newest-first |
| 5 | Page list parsing (`all`, ranges, negatives, `append`) | `PdfUtil.getPages/getPagesRange` | §3.3 |
| 6 | Position parsing + correction | `PdfUtil.getPositionOnPage/correctPositionSignature` | integers only |
| 7 | Append vs full rewrite decision | `PdfUtil.getAppendMode` | §5.1 |
| 8 | PDF writer: header, xref table/stream, object streams, `/ITXT`, Info `/ModDate`, XMP ModifyDate, `/ID` | iText `PdfStamperImp`, `PdfWriter` | §5.2; deterministic except `/ID` |
| 9 | Signature dictionary, 80-byte ByteRange, `2S+2` Contents, hex padding | `PdfSessionManager`, iText `PdfSignatureAppearance.preClose/close` | §5.3 |
| 10 | PDF date format | iText `PdfDate` | §5.4 |
| 11 | Field/widget creation, naming `SignatureN`, flags 132, multi-page duplication, rotation fix | iText `preClose`, `PdfStamperImp.addAnnotation` | §5.5 |
| 12 | Existing field signing | iText `setVisibleSignature(String)` | §5.5, §8.10 |
| 13 | AcroForm `/SigFlags 3`, `/DA`, `/DR` Helv/ZaDb, NeedAppearances removal | iText | §5.2 |
| 14 | Appearance n0/n2/FRM (+ n1/n3/n4 legacy) | iText `getAppearance` (TOP_SECTION 0) | §5.6 |
| 15 | Default text, tokens, date formatting | `PdfSessionManager.getDefaultLayer2Text`, `PdfVisibleAreasUtils.getLayerText` | §8.2–§8.3; needs Java X500Principal string |
| 16 | Obfuscation mask | `PdfTextMask`, `PdfVisibleAreasUtils.obfuscateIds` | §8.4 |
| 17 | Fonts (std-14 / FreeFont for PDF/A-1), simulated styles, colours | `PdfVisibleAreasUtils.getFont`, iText `PdfChunk` | §8.5 |
| 18 | ColumnText layout (wrap, leading, truncation) | iText `ColumnText` | §8.6 |
| 19 | Rubric image normalisation & fit | `PdfPreProcessor.getImage`, `ImageUtils`, iText | §8.6.1 |
| 20 | Rotated appearance + fitText | `PdfVisibleAreasUtils.buildRotatedSignatureImage` | §8.7 |
| 21 | DocMDP certification | iText `addDocMDP` | §5.7 |
| 22 | Certified-input check | `PdfUtil.checkPdfCertification` | §9.3 |
| 23 | Unregistered signatures check | `PdfUtil.pdfHasUnregisteredSignatures` | §9.2 |
| 24 | Usage rights removal | iText `PdfReader.removeUsageRights` | §4 step 9 |
| 25 | Encryption read (RC4/AES-128/AES-256), owner-access requirement, re-encryption of new objects | iText `PdfReader`, `PdfEncryption` | §5.8, §9.4 |
| 26 | Password exceptions & retry protocol | `PdfUtil.getPdfReader`, exception classes | §9.4, §12.7 |
| 27 | XMP signature history for PDF/A | `XmpHelper` | §5.10 |
| 28 | PDF/A-1 detection (no compression, embedded fonts) | `PdfUtil.isPdfA1` | §9.5 |
| 29 | Stamp image (`image*`) and attachment (`attach*`) | `PdfPreProcessor` | §5.9 |
| 30 | CAdES signed attributes for PAdES (no signingTime) | `PAdESTriPhaseSigner.preSign`, `CAdESUtils` | §6.3 |
| 31 | SignedData assembly (v1, IssuerAndSerial, NULL params, rsaEncryption) | `CAdESTriPhaseSigner.postSign` | §6.2 |
| 32 | Reserved size check | `PAdESTriPhaseSigner.insertSignatureOnPdf` | §6.5 |
| 33 | Signature timestamp (intended) | `PdfTimestamper.addCmsTimeStamp`, `CMSTimestamper.addTimestamp` | §7.2; Java currently no-op (§7.4) |
| 34 | Document timestamp `/DocTimeStamp` (intended) | `PdfTimestamper.timestampPdf` | §7.3; Java currently fails (§7.4) |
| 35 | RFC 3161 client (http/https/socket, auth, TLS options) | `CMSTimestamper`, `TsaParams` | §7.5 |
| 36 | Enhancer hook | `AOPDFSigner` static init | §6.6 (optional) |
| 37 | Triphase client protocol | `AOPDFTriPhaseSigner`, `PDFTriPhaseSignerUtil` | §11.3 |
| 38 | Triphase server PAdES pre/post + PID/TIME/PRE/HMAC, ID replacement | `PAdESTriPhasePreProcessor`, `PAdESTriPhaseSigner.postSign`, `SignatureService` | §11.2, §11.5; determinism |
| 39 | Triphase error mapping `ERR-21` | `PDFTriPhaseSignerUtil.buildInternalException` | §11.4 |
| 40 | PDF validation | `ValidatePdfSignature` | §10.1 |
| 41 | Form-change check | `DataAnalizerUtil.checkPDFForm` | §10.2 |
| 42 | Shadow-attack check (PDFBox 40 dpi gray pixel diff, overlap) | `DataAnalizerUtil.checkPdfShadowAttack` | §10.3; renderer differences may change results |
| 43 | PAdES profile detection | `SignatureFormatDetectorPadesCades.resolvePDFFormat` | §10.4 |
| 44 | PSA parameter policy per caller | `SignPanel`, protocol launchers, `SignatureService`, `TriPhaseHelper` | §10.6 |
| 45 | PAdES preferences & extraParams mapping | `PreferencesManager`, `ExtraParamsHelper`, `PreferencesPanelPades` | §12.1 |
| 46 | Empty-field chooser dialog | `PdfEmptySignatureFieldsChooserDialog.selectField`, `VisiblePdfSignatureManager` | §12.2 |
| 47 | Area selection, coordinate maths, page scope, size limits 30/45/1350 | `SignPdfUiPanel`, `PageLabel`, `SignPdfDialog` | §12.3–§12.4 |
| 48 | Lazy page rendering (75 dpi, ±4 pages) | `Pdf2ImagesConverter`, `PdfDocument` | §12.3 |
| 49 | Appearance editor + remembered settings | `SignPdfUiPanelPreview`, `FontResource`, `ColorResource` | §12.5 |
| 50 | Stamp panel | `SignPdfUiPanelStamp` | §12.6 |
| 51 | Protocol `visibleSignature`/`visibleAppearance` | `ProtocolInvocationLauncherSign(AndSave)` | §12.6 |
| 52 | Confirm/password retry UX | `SignPanelSignTask`, protocol launchers | §12.7 |
| 53 | Error codes | `PdfErrorCode` | §13 |
