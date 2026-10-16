# 02 — CMS (PKCS#7), CAdES and CAdES-ASiC-S signature formats

Implementation spec for a 1:1 Rust re-implementation of the AutoFirma ASN.1 signature formats.
It describes the Java behaviour exactly (including bugs), so that a Rust implementation can produce
structurally equivalent output without reading the Java sources.

* Source baseline: repository at commit `0d7f3cf01` (branch `main`).
* ASN.1 library used by Java: **SpongyCastle 1.58.0.0** (`com.madgag.spongycastle`, a repackaged Bouncy Castle 1.58).
  Many "invisible" encoding decisions come from it; they are made explicit in §4.6.
* Modules covered: `afirma-crypto-core-pkcs7`, `afirma-crypto-cms`, `afirma-crypto-cades`,
  `afirma-crypto-cades-multi`, `afirma-crypto-core-pkcs7-tsp`, `afirma-crypto-cadestri-client`,
  CAdES parts of `afirma-crypto-validation`, server-side CAdES triphase processors
  (`afirma-server-triphase-signer-core`, only to explain the pre/post split), and helpers in `afirma-core`.

Conventions used below:

* "Java `X`" means the Java class `X`; full paths are in §15.
* `extraParams` = the `java.util.Properties` bag passed to every operation (string keys, string values).
* "parseBoolean" = Java `Boolean.parseBoolean`: true only for the case-insensitive string `"true"`; anything else (including absent) is false.
* OIDs are dotted strings. `NULL` = ASN.1 `NULL` (`05 00`).
* "DER-sorted SET" = SET OF elements sorted by the byte-wise comparison of their complete DER encodings (§4.6).

---

## 0. Table of contents

1. Signer API surface
2. Extra parameters (all keys)
3. Algorithms
4. CAdES signature (sign) — exact ASN.1 output
5. CMS / PKCS#7 signature (sign) — exact ASN.1 output
6. Co-signature (cosign)
7. Counter-signature (countersign)
8. Long-term attributes guard
9. Timestamps (RFC 3161), CAdES-T
10. CAdES-ASiC-S container
11. Triphase split (pre-sign / post-sign)
12. Reading operations and format detection
13. Validation (`afirma-crypto-validation`)
14. Spanish defaults, hard-coded values and gotchas
15. Parity checklist
16. Appendices (OID reference, worked DER-ordering example, fixtures)

---

## 1. Signer API surface

### 1.1 Interfaces

Every format handler implements `AOSigner` (= `AOSimpleSigner` + `AOCoSigner` + `AOCounterSigner` + queries):

| Operation | Java signature (simplified) | Meaning |
|---|---|---|
| sign | `byte[] sign(byte[] data, String algorithm, PrivateKey key, Certificate[] certChain, Properties extraParams)` | New signature over `data`. `certChain[0]` is the signer certificate. |
| cosign (with data) | `byte[] cosign(byte[] data, byte[] sign, String algorithm, PrivateKey key, Certificate[] certChain, Properties extraParams)` | Add a parallel SignerInfo to an existing SignedData, using `data` (or its hash) as content. |
| cosign (no data) | `byte[] cosign(byte[] sign, String algorithm, PrivateKey key, Certificate[] certChain, Properties extraParams)` | Same, content/digest taken from the existing signature. |
| countersign | `byte[] countersign(byte[] sign, String algorithm, CounterSignTarget targetType, Object[] targets, PrivateKey key, Certificate[] certChain, Properties extraParams)` | Add counterSignature unsigned attributes to selected SignerInfos. |
| getSignersStructure | `AOTreeModel getSignersStructure(byte[] sign, [Properties params,] boolean asSimpleSignInfo)` | Tree of signers (§12.1). |
| isSign | `boolean isSign(byte[] data[, Properties params])` | Is this blob a signature this handler can multi-sign (§12.3). |
| isValidDataFile | `boolean isValidDataFile(byte[] data)` | Can these bytes be signed. |
| getSignedName | `String getSignedName(String originalName, String inText)` | Suggested output file name. |
| getData | `byte[] getData(byte[] sign[, Properties params])` | Extract embedded signed content (`null` if detached). |
| getSignInfo | `AOSignInfo getSignInfo(byte[] sign[, Properties params])` | Format descriptor. |

`CounterSignTarget` enum (string form, parsed case-insensitively after trim by `CounterSignTarget.getTarget`):
`SIGNERS("signers")`, `NODES("nodes")`, `TREE("tree")`, `LEAFS("leafs")`.

`AOSignInfo` carries `format` (string; "Desconocido" if null), plus unused-here `variant`, `urlSignObject`, `urlSignedData`, `b64VerificationCode`.

`AOSimpleSignInfo` carries: `certs` (X509Certificate[], must be non-empty or its constructor throws `IllegalArgumentException`), `signingTime` (Date or null), `signAlgorithm` (String), `signFormat` (unused here), `timestampingTime` (never set by the CMS/CAdES tree reader), `pkcs1` (signature value bytes).

### 1.2 Format identifiers and handler classes

| Format string (`AOSignConstants`) | Java handler | Used by auto-detection (`AOSignerFactory.getSigner(byte[])`) |
|---|---|---|
| `"CAdES"` (`SIGN_FORMAT_CADES`, also `DEFAULT_SIGN_FORMAT`) | `es.gob.afirma.signers.cades.AOCAdESSigner` | yes (1st) |
| `"CAdEStri"` | `es.gob.afirma.signers.cadestri.client.AOCAdESTriPhaseSigner` | no |
| `"CAdES-ASiC-S"` | `es.gob.afirma.signers.cades.asic.AOCAdESASiCSSigner` | yes (2nd) — but its `isSign` is always false (§12.3) |
| `"CAdES-ASiC-S-tri"` | `es.gob.afirma.signers.cadestri.client.asic.AOCAdESASiCSTriPhaseSigner` | no |
| `"CMS/PKCS#7"` | `es.gob.afirma.signers.cms.AOCMSSigner` | yes (3rd) |

Detection order of `AOSignerFactory.getSigner(byte[])`: CAdES, CAdES-ASiC-S, CMS/PKCS#7, FacturaE, XAdES, XAdES-ASiC-S, XMLDSig, PAdES, ODF, OOXML (only entries flagged as detectable). First handler whose `isSign` returns true wins.

Cosign/countersign for CAdES and CAdES-ASiC-S are delegated (by reflection) to classes in `afirma-crypto-cades-multi`:
`es.gob.afirma.signers.multi.cades.AOCAdESCoSigner`, `...AOCAdESCounterSigner`, `...asic.AOCAdESASiCSCoSigner`, `...asic.AOCAdESASiCSCounterSigner`. If missing → `InvalidLibraryException`.

### 1.3 Operation semantics per handler

#### CAdES (`AOCAdESSigner`)

| Operation | Behaviour |
|---|---|
| sign | `certChain` null/empty → `IllegalArgumentException`. `extraParams` is cloned (caller's object untouched). `algorithm` null → `IllegalArgumentException`; algorithm whose upper-case starts with `"MD"` → `AOException` code `600107` ("CAdES no permite huellas digitales MD2 o MD5"). If `profile` equalsIgnoreCase `baseline` and algorithm is SHA-1 based → warning only. Then "incompatible config" purge (§2.1 notes for `mode`/`signingCertificateV2`), `CAdESParameters.load` (§4.7), generation (§4), then timestamp attempt (§9 — **never succeeds in this version**). |
| cosign (both) | Clone params, same algorithm checks, delegate to `AOCAdESCoSigner` (§6.1). |
| countersign | Clone params, same algorithm checks, delegate to `AOCAdESCounterSigner` (§7.2). |
| getSignersStructure | If not `CAdESValidator.isCAdESValid(sign, false)` → `AOInvalidSignatureFormatException("Los datos introducidos no se corresponden con un objeto de firma CAdES")`. Else `ReadNodesTree.readNodesTree` (§12.1); any exception there → returns `null`. |
| isSign | null → false. Else `CAdESValidator.isCAdESSignedData(data, enforceCAdES=true)` (§12.3). |
| isValidDataFile | `data != null`. |
| getSignedName | `originalName + (inText ?? "") + ".csig"`. |
| getData | null → `IllegalArgumentException`. If not `isCAdESValid(sign,false)` → `AOInvalidSignatureFormatException`. Else `ObtainContentSignedData.obtainData` (§12.2). |
| getSignInfo | null → `IllegalArgumentException`; not `isSign` → `AOInvalidSignatureFormatException`; else `AOSignInfo("CAdES")`. |

#### CMS / PKCS#7 (`AOCMSSigner`)

The instance is stateful: fields `dataType` (always ends up `1.2.840.113549.1.7.1`), `atrib` and `uatrib` (maps OID→bytes, filled only via the public Java methods `addSignedAttribute(oid, bytes)` / `addUnsignedAttribute(oid, bytes)`; not reachable through extraParams).

| Operation | Behaviour |
|---|---|
| sign | `extraParams` null → empty. No algorithm validation; null/empty algorithm → `SHA512withRSA` (`AOSignConstants.DEFAULT_SIGN_ALGO`). See §5. |
| cosign (with data) | If `ValidateCMSSignedData.isCMSSignedData(sign)` → §6.2(a); else `AOInvalidSignatureFormatException("Los datos no se corresponden con una firma CMS valida")`. |
| cosign (no data) | Same detection → §6.2(b). |
| countersign | Same detection → §7.3. TREE, LEAFS, NODES (targets = `Integer` objects), SIGNERS (targets = `String` CNs) supported. `targetType == null` → returns `null` (no exception). |
| getSignersStructure | No validation; `ReadNodesTree.readNodesTree`; exception → `null`. |
| isSign | null → false; else `isCMSSignedData` (§12.3). |
| isValidDataFile | `data != null`. |
| getSignedName | `originalName + (inText ?? "") + ".csig"`. |
| getData | null → `IllegalArgumentException`; not CMS → `AOInvalidSignatureFormatException`; else `obtainData`. |
| getSignInfo | not CMS → `AOInvalidSignatureFormatException`; else `AOSignInfo("CMS/PKCS#7")`. |

#### CAdES-ASiC-S (`AOCAdESASiCSSigner`)

| Operation | Behaviour |
|---|---|
| sign | **Mutates the caller's `extraParams`** (if non-null) by putting `mode=explicit`. Produces a detached CAdES with `AOCAdESSigner.sign` over `data`, then wraps it into a ZIP (§10). ZIP I/O error → `AOException` code `214001`. |
| cosign (both) | Delegates to `AOCAdESASiCSCoSigner` (§6.3). `cosign(sign,…)` = `cosign(null, sign, …)`; the data argument is ignored anyway. |
| countersign | Delegates to `AOCAdESASiCSCounterSigner` (§7.4). |
| getSignersStructure | `AOCAdESSigner.getSignersStructure(<entry META-INF/signature.p7s>, asSimpleSignInfo)`. |
| isSign | **Bug: always false** (§12.3). |
| isValidDataFile | `data != null`. |
| getSignedName | `originalName + (inText ?? "") + ".asics"`. |
| getData | First data entry of the ZIP (§10). |
| getSignInfo | `AOCAdESSigner.getSignInfo(<signature entry>)` → returns format `"CAdES"` (not `"CAdES-ASiC-S"`). |

#### CAdES triphase client (`AOCAdESTriPhaseSigner`, `AOCAdESASiCSTriPhaseSigner`)

Pure protocol client (§11). `getSignersStructure`, `isSign`, `getData`, `getSignInfo` throw `UnsupportedOperationException`. `getSignedName` → `.csig` / `.asics`. Countersign requires TREE or LEAFS (else `IllegalArgumentException`) and writes `target=<tree|leafs>` into `extraParams` (mutating). ASiC triphase supports only sign.

---

## 2. Extra parameters

### 2.1 CAdES parameters (sign / cosign / countersign; ASiC-S uses the same set)

| Key | Type / values | Default | Effect on output |
|---|---|---|---|
| `mode` | `explicit` \| `implicit` | `explicit` (`AOSignConstants.DEFAULT_SIGN_MODE`) | CAdES: `explicit` compared with `equalsIgnoreCase`; **any other value means implicit**. Implicit → data embedded in `encapContentInfo.eContent`; explicit → eContent absent. Ignored (removed with a warning) when `precalculatedHashAlgorithm` is present (always explicit). In cosign: only implicit + data provided re-embeds content (§6.1). |
| `precalculatedHashAlgorithm` | digest name (any form accepted by §3.1) | absent | When present, `data` **is the digest**, not the content. messageDigest attribute = `data`; content never embedded; signing-certificate hash and fallback policy-hash algorithm use this algorithm. The SignerInfo `digestAlgorithm` still comes from the signature algorithm (gotcha G13). |
| `signingCertificateV2` | `true`/`false` | see rule | Rule (`CAdESParameters.load`): if algorithm ∈ {`SHA256withRSA`,`SHA384withRSA`,`SHA512withRSA`,`SHA256withECDSA`,`SHA384withECDSA`,`SHA512withECDSA`} (exact strings) → **V2 forced** (param removed with warning); else if param present → parseBoolean(param); else V2 unless the normalized digest name is exactly `SHA1`. |
| `includeOnlySignningCertificate` (sic, double "n") | `true`/`false` | `false` | sign only: `certificates` contains only `certChain[0]` instead of the full chain. Ignored by CAdES cosign/countersign (they append the full chain). Triphase client: also controls whether only the leaf cert is sent to the server. There is **no** correctly-spelled alias. |
| `doNotIncludePolicyOnSigningCertificate` | `true`/`false` | `false` | When `false` and the signer certificate has a `certificatePolicies` extension (2.5.29.32), its `PolicyInformation`s are copied into `SigningCertificate(V2).policies`. `true` omits them. |
| `includeSigningTimeAttribute` | `true`/`false` | included | If the key is present → parseBoolean decides; absent → included. Adds `signingTime` (UTCTime, system clock at parameter-load time). |
| `includeContentHintAttribute` | string | included | Only the case-insensitive value `"false"` disables `contentHints`. Ignored in advanced-profile countersignatures (they always get `contentHints{id-data}`, §7.2). |
| `contentTypeOid` | dotted OID | auto (§4.7) | `contentHints.contentType`. Not used for countersignatures. |
| `contentDescription` | string | auto (§4.7) | `contentHints.contentDescription` (UTF8String). |
| `includeMimeTypeAttribute` | `true`/`false` | `false` | parseBoolean. Adds `id-aa-ets-mimeType` (0.4.0.1733.2.1). Never in countersignatures. |
| `mimeType` | MIME string | auto (§4.7) | Value of the mimeType attribute (only used when `includeMimeTypeAttribute=true`). |
| `policyIdentifier` | OID, `urn:oid:<OID>` (case-insensitive prefix) | absent | Adds `sigPolicyId` (CAdES-EPES). Lower-cased and `urn:oid:` removed before use; a non-OID (e.g. URL) fails when building the attribute. |
| `policyIdentifierHash` | Base64 | absent | Policy hash. Absent or `"0"` → the identifier is downloaded as a URL and hashed (with `policyIdentifierHashAlgorithm` or **SHA-512**); since CAdES identifiers must be OIDs this practically always fails with `IllegalArgumentException`. Non-Base64 → `IllegalArgumentException`. |
| `policyIdentifierHashAlgorithm` | digest name (§3.1) | mandatory when hash given | `OtherHashAlgAndValue.hashAlgorithm`. Missing while hash given → `IllegalArgumentException`. Note `urn:oid:1.3.14.3.2.26` is **not** accepted (fails later), bare `1.3.14.3.2.26` or `http://www.w3.org/2000/09/xmldsig#sha1` are. |
| `policyQualifier` | URL | absent | Adds `SigPolicyQualifierInfo{id-spq-ets-uri, IA5String(URL)}`. Must parse as `java.net.URL` else `IllegalArgumentException`. Value written is `URL.toString()`. |
| `signerClaimedRoles` | roles separated by `\|` | absent | Adds `signerAttr` (advanced) or `signerAttrV2` (baseline) with one `role` (2.5.4.72) attribute per non-empty role (§4.4.9). |
| `signatureProductionCity` | string | absent | `SignerLocation.localityName` ([1]). |
| `signatureProductionPostalCode` | string, lines separated by `\n` | absent | **Not a postal code field**: split on `\n` (Java `String.split`, trailing empty strings dropped) into `SignerLocation.postalAddress` ([2], SEQUENCE OF UTF8String, max 6 lines; more → `IllegalArgumentException`). |
| `signatureProductionCountry` | string | absent | `SignerLocation.countryName` ([0]). |
| `signatureProductionProvince` | — | — | **Not supported by CAdES** (only XAdES/FacturaE). Ignored. |
| `commitmentTypeIndications` | integer ≥ 1 | absent | Number of commitment entries. Non-integer or < 1 → logged, ignored. |
| `commitmentTypeIndication<n>Identifier` | `1`..`6` | — | Commitment type for entry n (proofOfOrigin…proofOfCreation, §4.4.6). Unknown value → entry skipped. Missing → entry skipped. **Loop runs n = 0..N inclusive** (N+1 indexes). |
| `commitmentTypeIndication<n>CommitmentTypeQualifiers` | OIDs separated by `\|` | absent | Qualifiers for entry n, encoded as bare OIDs (§4.4.6). Invalid OID → `IllegalArgumentException`. |
| `profile` | `advanced` \| `baseline` | `advanced` | Only the exact (case-sensitive) string `baseline` activates baseline in `CAdESParameters` (the SHA-1 warning check uses equalsIgnoreCase). Baseline effects: roles go into `signerAttrV2` (0.4.0.19122.1.1) and countersignatures omit `contentHints`. Nothing else changes (issuerSerial is still included). |
| `allowSignLTSignature` | `true`/`false` | absent | Long-term-attribute guard for cosign/countersign (§8). |
| `tsa*`, `verifyHostname` | see §2.2 | | Intended for CAdES-T, **no effect in this version** (§9.4). |
| `headless` | — | — | Declared in `CAdESExtraParams`, not read by CAdES code. |
| `Provider.<PrivateKey class name>` | JCA provider name | absent | Read by `AOPkcs1Signer`: forces the JCA provider used for the PKCS#1 operation. |
| `expPolicy` | `FirmaAGE` \| `FirmaAGE18` | absent | **Not read by the signer**; expanded beforehand by the application layer via `ExtraParamsProcessor.expandProperties` (§2.3). |

Notes on "incompatible config" purge (`AOCAdESSigner.noticeIncompatibleConfig` for sign; `AOCAdESCoSigner.noticeIncompatibleConfig` for cosign):
* sign: if both `precalculatedHashAlgorithm` and `mode` present → `mode` removed. cosign: if `precalculatedHashAlgorithm` present → `mode` removed.
* both: if algorithm is in the SHA-2 list above and `signingCertificateV2` present → removed.

### 2.2 TSA parameters (`TsaParams(Properties)`, module `afirma-crypto-core-pkcs7-tsp`)

`TsaParams` construction fails (`IllegalArgumentException`) when `tsaURL` is absent → "no timestamp requested".

| Key | Default | Meaning |
|---|---|---|
| `tsaURL` | — (required) | TSA URI. Schemes (case-sensitive): `http`, `https`, `socket`. Others → `UnsupportedOperationException`. |
| `tsaPolicy` | `0.4.0.2023.1.1` | `TimeStampReq.reqPolicy` OID. (Javadoc wrongly says mandatory.) |
| `tsaHashAlgorithm` | `SHA-512` | Normalized with §3.1. Hash of the imprint. (Javadoc wrongly says SHA-1.) |
| `tsaRequireCert` | `true` | `certReq`; false only if value equalsIgnoreCase `"false"`. |
| `tsaUsr` / `tsaPwd` | absent | HTTP Basic auth (`Authorization: Basic base64(usr:pwd)`) if `tsaUsr` non-empty; `tsaPwd` may be null → literal `"null"` appended. |
| `tsaSslKeyStore` | absent | **Base64** of the client-cert keystore for HTTPS. |
| `tsaSslKeyStorePassword` | `""` | |
| `tsaSslKeyStoreType` | `PKCS12` | |
| `tsaSslTrustStore` | absent | Base64 trust store. If absent → **trust-all** TrustManager. |
| `tsaSslTrustStorePassword` | `""` | |
| `tsaSslTrustStoreType` | `PKCS12` | |
| `tsaExtensionOid` + `tsaExtensionValueBase64` | absent | One request extension; ignored (warning) unless both given. |
| `tsaExtensionCritical` | `false` | Criticality of that extension. |
| `verifyHostname` | `true` | HTTPS hostname verification (no `tsa` prefix). |
| `tsaSslPkcs12File`, `tsaSslPkcs12FilePassword` | — | **Documented** in `CAdESExtraParams`/extraparams.html but **never read**. Dead aliases. |

### 2.3 Policy expansion (`expPolicy`, `ExtraParamsProcessor.expandProperties(params, signedData, format)`)

Called by the application/protocol layer (desktop protocol handlers, server batch, miniapplet), not by the signers. For CAdES the `format` must be `CAdES` or `CAdEStri` (case-insensitive); `CAdES-ASiC-S` → `SignaturePolicyIncompatibilityException`.

Accepted values: `FirmaAGE`, `FirmaAGE18` (anything else → `SignaturePolicyIncompatibilityException`; note `FirmaAGE19` exists in `policy.properties` but is rejected). Expansion for CAdES:

1. If `mode` absent and data given: `mode = implicit` if `data.length < 1 048 576` else `explicit`.
2. `profile` forced to `advanced` (warning if it was `baseline`).
3. Policy properties set (overwriting existing values with a warning):

| expPolicy | policyIdentifier | policyIdentifierHashAlgorithm | policyIdentifierHash (CAdES) | policyQualifier |
|---|---|---|---|---|
| `FirmaAGE` (= v1.9) | `urn:oid:2.16.724.1.3.1.1.2.1.9` | `http://www.w3.org/2000/09/xmldsig#sha1` | `G7roucf600+f03r/o0bAOQ6WAs0=` | `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` |
| `FirmaAGE18` | `urn:oid:2.16.724.1.3.1.1.2.1.8` | `http://www.w3.org/2000/09/xmldsig#sha1` | `7SxX3erFuH31TvAw9LZ70N7p1vA=` (XAdES uses `V8lVVNGDCPen6VELRD1Ja8HARFk=`) | `https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf` |

4. `expPolicy` removed from the result.

### 2.4 CMS parameters (`AOCMSExtraParams`)

| Key | Default | Effect |
|---|---|---|
| `mode` | `explicit` | Compared with **case-sensitive** `equals("explicit")`; any other value = implicit. |
| `precalculatedHashAlgorithm` | absent | Presence only: `data` is the message digest; content omitted. **The value is never used** (digest assumed to match the signature algorithm). |
| `applySystemDate` | `true` | sign only: parseBoolean; adds `signingTime`. CMS cosign/countersign always add signingTime. |

### 2.5 CAdES-ASiC-S parameters

| Key | Default | Effect |
|---|---|---|
| `asicsFilename` | `dataobject.<ext>` | ZIP entry name for the signed data (§10). |
| `mode` | forced `explicit` | Overwritten (in the caller's Properties). |
| all CAdES keys | | Passed to the inner CAdES signer. |

### 2.6 Triphase parameters (client)

| Key | Effect |
|---|---|
| `serverUrl` | Triphase service URL (required; invalid → `IllegalArgumentException`). Removed from the params sent to the server. |
| `documentId` | Removed from the params sent to the server. |
| `target` | Set by the client for countersign (`tree`/`leafs`). |
| `SignatureId` | Server side: id of the `TriSign` (random UUID if absent). |
| `servicetimeout` | HTTP timeout (constant name in Pre/PostSigner). |
| `includeOnlySignningCertificate` | Client sends only the leaf cert (`cert` param = Base64URL(cert)); otherwise comma-separated Base64URL of the whole chain. |

---

## 3. Algorithms

### 3.1 Digest name normalization (`AOSignConstants.getDigestAlgorithmName(pseudoName)`)

Applied (upper-cased with `Locale.US`) in this order:

| Input (case-insensitive) | Result |
|---|---|
| `SHA`, `http://www.w3.org/2000/09/xmldsig#sha1`, `1.3.14.3.2.26`, anything starting with `SHA1` or `SHA-1` | `SHA1` |
| `http://www.w3.org/2001/04/xmlenc#sha256`, `2.16.840.1.101.3.4.2.1`, starts with `SHA256` or `SHA-256` | `SHA-256` |
| `2.16.840.1.101.3.4.2.2`, starts with `SHA384` or `SHA-384` | `SHA-384` |
| `http://www.w3.org/2001/04/xmlenc#sha512`, `2.16.840.1.101.3.4.2.3`, starts with `SHA512` or `SHA-512` | `SHA-512` |
| `http://www.w3.org/2001/04/xmlenc#ripemd160`, starts with `RIPEMD160`/`RIPEMD-160` | `RIPEMD160` (no OID → unusable) |
| contains `with` (case-sensitive) | recurse on the prefix before `with` |
| starts with `http://www.w3.org/2001/04/xmldsig-more#`, `http://www.w3.org/2000/09/xmldsig#`, `http://www.w3.org/2009/xmldsig11#` | recurse on the substring after the last `-` |
| otherwise | returned unchanged (warning) |

Consequences: `SHA224withRSA` → `SHA224`; `SHA3-256withRSA` → `SHA3-256`; `MD5withRSA` → `MD5`; none of these have a digest OID in `AOAlgorithmID` → operations fail with `IllegalArgumentException("Se desconoce el algoritmo …")` (wrapped). The xmldsig-more `sha384` URI also fails.

### 3.2 OID table (`AOAlgorithmID`)

Digest names → OID (all AlgorithmIdentifiers are written as `SEQUENCE { OID, NULL }`):

| Names | OID |
|---|---|
| `SHA1`, `SHA-1`, `SHA` | `1.3.14.3.2.26` |
| `SHA-224`, `SHA224` | `2.16.840.1.101.3.4.2.4` |
| `SHA-256`, `SHA256` | `2.16.840.1.101.3.4.2.1` |
| `SHA-384`, `SHA384` | `2.16.840.1.101.3.4.2.2` |
| `SHA-512`, `SHA512` | `2.16.840.1.101.3.4.2.3` |

Signature names → OID (`X` may also be written `SHA-X`; e.g. `SHA-256withRSA`):

| Name | OID | Name | OID |
|---|---|---|---|
| `RSA` | `1.2.840.113549.1.1.1` (rsaEncryption) | `DSA` | `1.2.840.10040.4.1` |
| `SHA1withRSA` | `1.2.840.113549.1.1.5` | `SHA1withDSA` | `1.2.840.10040.4.3` |
| `SHA224withRSA` | `1.2.840.113549.1.1.14` | `SHA224withDSA` | `2.16.840.1.101.3.4.3.1` |
| `SHA256withRSA` | `1.2.840.113549.1.1.11` | `SHA256withDSA` | `2.16.840.1.101.3.4.3.2` |
| `SHA384withRSA` | `1.2.840.113549.1.1.12` | `SHA384withDSA` | `2.16.840.1.101.3.4.3.3` |
| `SHA512withRSA` | `1.2.840.113549.1.1.13` | `SHA512withDSA` | `2.16.840.1.101.3.4.3.4` |
| `SHA1withECDSA` | `1.2.840.10045.4.1` | `SHA3-224withRSA` | `2.16.840.1.101.3.4.3.13` |
| `SHA224withECDSA` | `1.2.840.10045.4.3.1` | `SHA3-256withRSA` | `2.16.840.1.101.3.4.3.14` |
| `SHA256withECDSA` | `1.2.840.10045.4.3.2` | `SHA3-384withRSA` | `2.16.840.1.101.3.4.3.15` |
| `SHA384withECDSA` | `1.2.840.10045.4.3.3` | `SHA3-512withRSA` | `2.16.840.1.101.3.4.3.16` |
| `SHA512withECDSA` | `1.2.840.10045.4.3.4` | `SHA3-{224,256,384,512}withECDSA` | `2.16.840.1.101.3.4.3.{9,10,11,12}` |
| | | `SHA3-{224,256,384,512}withDSA` | `2.16.840.1.101.3.4.3.{5,6,7,8}` |

The SHA-3 signature OIDs exist but **SHA-3 is unusable** (no SHA-3 digest OIDs). **RSA-PSS is not supported** (a name such as `SHA256withRSAandMGF1` normalizes to `SHA256withRSA` for the PKCS#1 operation, producing PKCS#1 v1.5). EdDSA not supported.

### 3.3 SignerInfo `signatureAlgorithm` (a.k.a. digestEncryptionAlgorithm) per code path

Always `SEQUENCE { OID, NULL }` — **NULL parameters even for ECDSA/DSA** (non-conformant with RFC 5758, required for parity).

| Code path | Rule | Example (`SHA256withRSA`, RSA cert) | Example (`SHA256withECDSA`, EC cert) |
|---|---|---|---|
| CAdES sign (`CAdESTriPhaseSigner.postSign`, also server triphase sign) | if the **requested algorithm string** contains `withRSA` → `1.2.840.113549.1.1.1`; else OID of the requested algorithm string | rsaEncryption | `1.2.840.10045.4.3.2` |
| CAdES cosign (`CAdESCoSigner`), CAdES countersign (`CAdESCounterSigner`), server triphase cosign/countersign | OID of `composeSignatureAlgorithmName(digest(algorithm), certChain[0].publicKey.algorithm)` | **`1.2.840.113549.1.1.11`** (sha256WithRSAEncryption) | `1.2.840.10045.4.3.2` |
| CMS sign / cosign / countersign | same rule as CAdES sign | rsaEncryption | `1.2.840.10045.4.3.2` |

`composeSignatureAlgorithmName(alg, keyType)` = `getDigestAlgorithmName(alg)` with `-` removed + suffix: key type `RSA` → `withRSA`, `DSA` → `withDSA`, starts with `EC` → `withECDSA`, else `IllegalArgumentException`.

### 3.4 Producing the signature value

* CAdES (all paths) and triphase client: `AOPkcs1Signer.sign(bytesToSign, algorithm, key, certChain, extraParams)`:
  1. JCA algorithm = `composeSignatureAlgorithmName(algorithm, key.getAlgorithm())` (so the *key* decides RSA/ECDSA/DSA, not the requested string).
  2. Provider from `extraParams["Provider." + key.getClass().getName()]` if set.
  3. Sign. RSA → PKCS#1 v1.5 (DigestInfo). ECDSA/DSA → DER `SEQUENCE { r INTEGER, s INTEGER }` (JCA default).
  4. **Post-sign verification** (ETSI TS 119 102-1): verifies with `certChain[0].getPublicKey()`; mismatch → `AOException` code `200112` ("La firma no se ha generado con el certificado seleccionado"); verification error → `200113`. Skipped (warning) if no chain.
  * Error mapping: unsupported algorithm `600107`; init failure `200110`; sign failure `200111`; smart-card cancellations/PIN errors mapped to specific exceptions.
* CMS (`CmsUtil.firma`): `Signature.getInstance(signatureAlgorithm)` with the requested string as-is (no key-type composition, no post-verification).

The bytes signed are **always the DER encoding of the signed attributes as a `SET OF` (tag `0x31`)**, never the `[0]` IMPLICIT form.

### 3.5 Default algorithm selection

| Layer | Default |
|---|---|
| `AOCAdESSigner` (library) | none — `null` → `IllegalArgumentException`. |
| `AOCMSSigner` | null or empty → `SHA512withRSA` (`AOSignConstants.DEFAULT_SIGN_ALGO`). |
| Desktop app (afirma-simple) | preference `signatureHashAlgorithm` (default `SHA256`) composed with the key type → e.g. `SHA256withRSA`, `SHA256withECDSA`. |
| Web/protocol invocation | algorithm param composed with key type via `composeSignatureAlgorithmName`. |

The CAdES/CMS signers expect callers to pass an algorithm already composed for the key type (otherwise, CAdES sign would write rsaEncryption next to an ECDSA value).

---

## 4. CAdES signature (sign) — exact ASN.1 output

### 4.1 Pipeline

```
AOCAdESSigner.sign
  params = clone(extraParams)
  checkAlgorithm(algorithm, params)                 // §1.3
  noticeIncompatibleConfig(algorithm, params)       // §2.1
  cfg = CAdESParameters.load(data, algorithm, params)   // §4.7 (signingTime = now)
  GenCAdESEPESSignedData.generateSignedData(algorithm, key, chain, cfg):
     chain' = cfg.includedOnlySigningCertificate ? [chain[0]] : chain
     pre    = CAdESTriPhaseSigner.preSign(chain', now, cfg)      // DER SET OF signedAttrs
     sig    = AOPkcs1Signer.sign(pre, algorithm, key, chain', cfg.extraParams)
     out    = CAdESTriPhaseSigner.postSign(algorithm, cfg.contentData, chain', sig, pre)
  out = applyTimeStamp(out, params)                 // §9.4: always returns out unchanged
```

### 4.2 Top-level structure

```
ContentInfo ::= SEQUENCE {
  contentType  OID 1.2.840.113549.1.7.2            -- signedData
  content [0] EXPLICIT SignedData
}
SignedData ::= SEQUENCE {
  version          INTEGER 1                       -- computed, see below
  digestAlgorithms SET { SEQUENCE { <digest OID>, NULL } }    -- exactly one entry
  encapContentInfo SEQUENCE {
      eContentType OID 1.2.840.113549.1.7.1        -- id-data, always
      eContent [0] EXPLICIT OCTET STRING <data>    -- ONLY in implicit mode
  }
  certificates [0] IMPLICIT SET OF Certificate     -- chain' (DER-sorted, see 4.6)
  -- crls: absent
  signerInfos SET { SignerInfo }
}
```

* `<digest OID>` = OID of `getDigestAlgorithmName(algorithm)` (the **signature** algorithm, even with `precalculatedHashAlgorithm`).
* eContent is a primitive (definite-length) OCTET STRING with the raw data bytes. Empty data in implicit mode → `OCTET STRING` of length 0.
* Certificates are re-encoded from the Java `Certificate.getEncoded()` bytes (identical DER). A certificate that fails to parse is skipped (logged).
* SignedData `version` (Bouncy Castle `SignedData` constructor, RFC 5652 §5.1): 5 if any `[3]` other-cert or tagged CRL; 4 if v2 attribute certs; 3 if v1 attribute certs, any SignerInfo v3, or eContentType ≠ id-data; else **1**. AutoFirma output is always 1 (unless re-wrapping foreign structures).
* Whole output is encoded with `getEncoded(DER)` (definite lengths everywhere).

### 4.3 SignerInfo

```
SignerInfo ::= SEQUENCE {
  version             INTEGER 1                    -- 1 because sid is issuerAndSerialNumber
  sid                 IssuerAndSerialNumber ::= SEQUENCE {
                          issuer  Name             -- exact bytes of TBSCertificate.issuer of chain[0]
                          serialNumber INTEGER     -- TBSCertificate.serialNumber
                      }
  digestAlgorithm     SEQUENCE { <digest OID>, NULL }
  signedAttrs [0] IMPLICIT SET OF Attribute        -- DER-sorted; = `pre` with tag 0x31 → 0xA0
  signatureAlgorithm  SEQUENCE { <§3.3 OID>, NULL }
  signature           OCTET STRING <sig>
  -- unsignedAttrs: absent
}
```

AutoFirma never produces `subjectKeyIdentifier` sids (SignerInfo v3).

### 4.4 Signed attributes

`CAdESUtils.generateSignedAttributes(cert, cfg, isCountersign)` builds them in the **logical order** below; the emitted order is the DER sort of §4.6 (worked example in §16.2). Every attribute is `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }` and every attribute here has exactly one value, except that some attribute *types* may appear in several Attribute entries (commitment types).

| # | Attribute | OID | Present when |
|---|---|---|---|
| 1 | contentType | `1.2.840.113549.1.9.3` | not a countersignature |
| 2 | messageDigest | `1.2.840.113549.1.9.4` | always (missing data and digest → error) |
| 3a | signingCertificateV2 | `1.2.840.113549.1.9.16.2.47` | `cfg.signingCertificateV2` |
| 3b | signingCertificate (v1) | `1.2.840.113549.1.9.16.2.12` | otherwise |
| 4 | sigPolicyId (signature-policy-identifier) | `1.2.840.113549.1.9.16.2.15` | `policyIdentifier` configured |
| 5 | contentHints | `1.2.840.113549.1.9.16.2.4` | `cfg.contentTypeOid != null` and not (countersignature ∧ baseline) |
| 6 | commitmentTypeIndication (one Attribute per indication) | `1.2.840.113549.1.9.16.2.16` | commitment params |
| 7 | signerLocation | `1.2.840.113549.1.9.16.2.17` | any of city/country/postal-address params present |
| 8 | signerAttr / signerAttrV2 | `1.2.840.113549.1.9.16.2.18` / `0.4.0.19122.1.1` | `signerClaimedRoles` with ≥1 non-empty role |
| 9 | signingTime | `1.2.840.113549.1.9.5` | `cfg.signingTime != null` (default yes) |
| 10 | mimeType | `0.4.0.1733.2.1` | `cfg.mimeType != null` and not a countersignature |

#### 4.4.1 contentType
`SET { OID 1.2.840.113549.1.7.1 }` (always id-data, regardless of `contentTypeOid`).

#### 4.4.2 messageDigest
`SET { OCTET STRING md }` where `md` = `cfg.dataDigest` if set, else `digest(cfg.digestAlgorithm, cfg.contentData)`. In sign: digest of the data with the signature algorithm's digest (or the provided precalculated digest).

#### 4.4.3 signingCertificateV2 (RFC 5035)
```
SET { SigningCertificateV2 ::= SEQUENCE {
  certs SEQUENCE OF ESSCertIDv2 {            -- exactly one
    ESSCertIDv2 ::= SEQUENCE {
      hashAlgorithm SEQUENCE { <hash OID>, NULL }   -- OMITTED when hash is SHA-256 (DER DEFAULT)
      certHash      OCTET STRING  digest(cfg.digestAlgorithm, chain[0].getEncoded())
      issuerSerial  IssuerSerial ::= SEQUENCE {
          issuer  GeneralNames ::= SEQUENCE { [4] EXPLICIT Name }   -- directoryName = issuer DER of chain[0]
          serialNumber INTEGER
      }
    }
  }
  policies SEQUENCE OF PolicyInformation OPTIONAL   -- see below
} }
```
* hash algorithm = `cfg.digestAlgorithm` (signature digest, or precalculated algorithm).
* `issuerSerial` is always included (`includedIssuerSerial` is hard-wired to true; the baseline exception is commented out).
* `policies`: present iff `doNotIncludePolicyOnSigningCertificate` is not true **and** the signer certificate has extension `2.5.29.32`. The `certificatePolicies` extension value is parsed and each `PolicyInformation` (policyIdentifier + qualifiers) re-emitted in the original order (§16.3 fixture shows a 2.16.724.1.4.2.2.1.2.11 policy with CPS/UserNotice qualifiers copied verbatim).

#### 4.4.4 signingCertificate v1 (RFC 2634)
```
SET { SigningCertificate ::= SEQUENCE {
  certs SEQUENCE OF ESSCertID { ESSCertID ::= SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial } }
  policies SEQUENCE OF PolicyInformation OPTIONAL
} }
```
`certHash` uses `cfg.digestAlgorithm` (SHA-1 in the normal case; may be another hash if `signingCertificateV2=false` with a non-SHA-1 algorithm outside the SHA-2 list — non-standard but reproducible).

#### 4.4.5 sigPolicyId (signature-policy-identifier, RFC 5126 §5.8.1)
```
SET { SignaturePolicyId ::= SEQUENCE {
  sigPolicyId   OID  <policyIdentifier, lower-cased, "urn:oid:" removed>
  sigPolicyHash OtherHashAlgAndValue ::= SEQUENCE {
      hashAlgorithm SEQUENCE { <OID of normalized policyIdentifierHashAlgorithm>, NULL }
      hashValue     OCTET STRING  base64decode(policyIdentifierHash)
  }
  sigPolicyQualifiers SEQUENCE {                      -- only if policyQualifier given
      SigPolicyQualifierInfo ::= SEQUENCE { OID 1.2.840.113549.1.9.16.5.1, IA5String <URL> }
  }
} }
```
The `SignaturePolicyIdentifier` CHOICE is encoded directly as `SignaturePolicyId` (no implied policy). Code fallbacks (unreachable through `AdESPolicy`): missing algorithm → signature digest algorithm; missing hash → `OCTET STRING 00`.

AGE v1.9 example (from `expPolicy=FirmaAGE`): sigPolicyId `2.16.724.1.3.1.1.2.1.9`, hash `SEQUENCE{1.3.14.3.2.26, NULL}`, value = 20 bytes of `G7roucf600+f03r/o0bAOQ6WAs0=`, qualifier `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf`.

#### 4.4.6 commitmentTypeIndication
One Attribute **per** configured indication (same OID repeated):
```
SET { CommitmentTypeIndication ::= SEQUENCE {
  commitmentTypeId OID 1.2.840.113549.1.9.16.6.<n>
  SEQUENCE { OID q1, OID q2, … }                  -- only when qualifiers given
} }
```
`<n>` mapping of `commitmentTypeIndication<i>Identifier`: `1`→6.1 proofOfOrigin, `2`→6.2 proofOfReceipt, `3`→6.3 proofOfDelivery, `4`→6.4 proofOfSender, `5`→6.5 proofOfApproval, `6`→6.6 proofOfCreation.
**Non-standard**: qualifiers are a SEQUENCE of bare OIDs, not `SEQUENCE OF CommitmentTypeQualifier{OID, ANY}`. Indications are generated for indexes `0..N` inclusive in index order (then DER-sorted as attributes).

#### 4.4.7 signerLocation (RFC 5126 §5.11.2)
```
SET { SignerLocation ::= SEQUENCE {
  [0] EXPLICIT UTF8String countryName       -- if signatureProductionCountry != null
  [1] EXPLICIT UTF8String localityName      -- if signatureProductionCity != null
  [2] EXPLICIT SEQUENCE OF UTF8String       -- lines of signatureProductionPostalCode split on "\n"
} }
```
Empty strings are not filtered (an empty param yields an empty UTF8String). The attribute is omitted only when all three are absent.

#### 4.4.8 contentHints (RFC 2634 §2.9)
```
SET { ContentHints ::= SEQUENCE {
  contentDescription UTF8String OPTIONAL     -- FIRST, if description != null
  contentType        OID
} }
```
Values from §4.7. Typical default: `SEQUENCE { UTF8String "binary", OID 1.2.840.113549.1.7.1 }`.

#### 4.4.9 signerAttr (advanced) / signerAttrV2 (baseline)
```
SET { SEQUENCE {
  [0] EXPLICIT SEQUENCE {                       -- claimedAttributes
     Attribute { OID 2.5.4.72 (id-at-role), SET { UTF8String role1 } },
     Attribute { OID 2.5.4.72, SET { UTF8String role2 } }, …   -- one Attribute per role, input order
  }
} }
```
Attribute OID: `1.2.840.113549.1.9.16.2.18` when profile is advanced, `0.4.0.19122.1.1` when baseline. Roles are split on the literal `|`; empty roles skipped; no roles left → attribute omitted. Role values are plain UTF8String (not X.509 `RoleSyntax`).

#### 4.4.10 signingTime
`SET { UTCTime "YYMMDDHHMMSSZ" }` — **always UTCTime**, always with seconds, always `Z`, UTC, even for dates ≥ 2050 (no GeneralizedTime switch). Value = system time when `CAdESParameters.load` ran (for countersignatures: one timestamp shared by all countersignatures created in that call).

#### 4.4.11 mimeType
`SET { UTF8String <mime> }`.

### 4.5 Unsigned attributes
None for CAdES sign in this version (the timestamp path is dead, §9.4).

### 4.6 DER encoding rules inherited from SpongyCastle 1.58 (must be reproduced)

1. All outputs are DER: definite lengths, primitive OCTET STRINGs, `BOOLEAN TRUE = FF`.
2. **Every SET is emitted sorted** by unsigned byte-wise comparison of each element's full DER encoding (tag+length+value); when one encoding is a prefix of the other, the shorter sorts first. This applies to: signedAttrs, unsignedAttrs, attrValues, `digestAlgorithms`, `certificates`, `signerInfos`, counterSignature value sets.
   * Consequence: attribute order is effectively "short encodings first" (the length byte is the 2nd byte), e.g. contentType, signingTime, contentHints, messageDigest, then long-form ones (signingCertificateV2…).
   * Certificates are **not** in chain order; they are DER-sorted.
   * SignerInfos are DER-sorted (a cosignature is not necessarily last).
3. On cosign/countersign the **whole input structure is parsed and re-encoded in DER**: indefinite lengths become definite, constructed OCTET STRINGs (only possible in eContent) are problematic (§6.1), and any SET of the original that was not DER-sorted gets re-sorted (would break third-party signatures whose signedAttrs were not DER-sorted; AutoFirma does this silently).
4. AlgorithmIdentifiers built by AutoFirma always carry explicit `NULL` parameters (except the omitted default in ESSCertIDv2).
5. `Name`/issuer values are copied byte-for-byte from the certificate (string types preserved).

### 4.7 `CAdESParameters.load(data, signedData?, algorithm, config)` — exact decision procedure

Inputs: `data` (content, or digest when `precalculatedHashAlgorithm`), optional previous `signedData` (cosign only), `algorithm`, `config`.

```
1. signingCertificateV2  := rule of §2.1
2. pre := config["precalculatedHashAlgorithm"]
   mode := config["mode"] or "explicit"
   omitContent := (pre != null) || equalsIgnoreCase(mode, "explicit")
   contentNeeded := !omitContent
3. if pre != null:
       digestAlgorithm := normalize(pre); dataDigest := data; contentData := null
   else:
       digestAlgorithm := normalize(algorithm)
       contentData := omitContent ? null : data
       dataDigest  := data != null ? H(digestAlgorithm, data) : null
4. claimedRoles := config["signerClaimedRoles"] split on "|" (if non-empty string)
5. includedPolicyOnSigningCertificate := !parseBoolean(config["doNotIncludePolicyOnSigningCertificate"])
6. externalPolicy := AdESPolicy.buildAdESPolicy(config)   // null if no policyIdentifier (§2.1)
7. includedOnlySigningCertificate := parseBoolean(config["includeOnlySignningCertificate"])
8. commitmentTypeIndications := §4.4.6 parsing
9. signingTime := (key "includeSigningTimeAttribute" absent || parseBoolean(value)) ? now : null
10. contentHintNeeded := key "includeContentHintAttribute" absent || value !equalsIgnoreCase "false"
    mimetypeNeeded    := parseBoolean(config["includeMimeTypeAttribute"])
    if contentHintNeeded || mimetypeNeeded:
       oid  := config["contentTypeOid"]; desc := config["contentDescription"]; mime := config["mimeType"]
       a) if mimetypeNeeded && mime == null && oid != null:
              mime := OID→MIME table(oid)            // §12.4; NOTE id-data maps to "data"
              if mime == "application/octet-stream": mime := null
       b) if ((contentHintNeeded && oid == null) || (mimetypeNeeded && mime == null)) && signedData != null:
              for each previous SignerInfo until something found:
                 if mimetypeNeeded && mime == null && it has attr 0.4.0.1733.2.1:
                       mime := value.toString(); found
                 if contentHintNeeded && oid == null && it has contentHints with ≥1 value:
                       oid := contentHints.contentType; if desc == null: desc := contentHints.contentDescription; found
                 if mime != null && oid == null: oid := MIME→OID(mime); if oid == id-data: oid := null
                 else if mimetypeNeeded && mime == null && oid != null && oid != id-data:
                       mime := OID→MIME(oid); if mime == "application/octet-stream": mime := null
       c) if ((contentHintNeeded && oid == null) || (mimetypeNeeded && mime == null)) && data != null:
              det := MimeHelper(data)                 // §12.4 (JMimeMagic + XML + Office analysis)
              if contentHintNeeded && oid == null:  oid := MIME→OID(det.mime); if oid == id-data: oid := null
              if contentHintNeeded && desc == null: desc := det.description
              if mimetypeNeeded && mime == null:    mime := det.mime
       d) if contentHintNeeded: contentTypeOid := oid ?? "1.2.840.113549.1.7.1"
                                contentDescription := desc ?? "binary"
          if mimetypeNeeded:    mimeType := mime ?? "application/octet-stream"
11. metadata := SignerLocation params (§4.4.7) or null
12. profileSet := (config["profile"] == "baseline") ? "baseline" : "advanced"     // case-sensitive
13. includedIssuerSerial := true (hard-wired)
```

Observations for parity:
* In explicit mode `data` is still analysed for content hints (step 10c).
* With `precalculatedHashAlgorithm`, the *digest bytes* are fed to MIME detection (→ generic: id-data / "binary" in practice, unless detection matches something).
* In cosign `data` may be null: then content hints come from previous signers or fall back to `id-data`/`"binary"` (the embedded content is **not** analysed).

---

## 5. CMS / PKCS#7 signature (sign) — exact ASN.1 output

`AOCMSSigner.sign` → `GenSignedData.generateSignedData`:

```
ContentInfo { 1.2.840.113549.1.7.2, [0] SignedData {
  version 1
  digestAlgorithms SET { SEQUENCE { <digest OID of algorithm>, NULL } }
  encapContentInfo SEQUENCE { 1.2.840.113549.1.7.1 [, [0] EXPLICIT OCTET STRING data ] }   -- content if !omitContent
  certificates [0] IMPLICIT SET OF Certificate     -- full chain (DER-sorted); an empty chain fails (chain[0] needed)
  -- crls absent
  signerInfos SET { SignerInfo {
     version 1, sid IssuerAndSerialNumber(chain[0]),
     digestAlgorithm SEQUENCE { <digest OID>, NULL },
     signedAttrs [0] IMPLICIT SET {                  -- DER-sorted
        contentType  { 1.2.840.113549.1.9.3, SET { 1.2.840.113549.1.7.1 } },
        signingTime  { 1.2.840.113549.1.9.5, SET { UTCTime now } }      -- if applySystemDate (default true)
        messageDigest{ 1.2.840.113549.1.9.4, SET { OCTET STRING md } },
        <custom: OID, SET { PrintableString(new String(bytes, platform charset)) }>…   -- addSignedAttribute only
     }
     signatureAlgorithm SEQUENCE { rsaEncryption | <sig OID>, NULL }     -- §3.3
     signature OCTET STRING
     unsignedAttrs [1] IMPLICIT SET { custom PrintableString attrs }      -- only if addUnsignedAttribute used
  } }
} }
```

* `omitContent` = `mode.equals("explicit")` (case-sensitive) `|| precalculatedHashAlgorithm present`.
* `md` = `data` when `precalculatedHashAlgorithm` present (and non-empty), else `H(digest(algorithm), data)`.
* No signingCertificate, no contentHints: this is plain PKCS#7/CMS (compatible with PKCS#7 v1.5 consumers).
* Signature produced with `Signature.getInstance(algorithm)` (§3.4) over the DER SET.
* No timestamp support.

---

## 6. Co-signature (cosign)

### 6.1 CAdES cosign (`AOCAdESCoSigner` + `CAdESCoSigner.coSigner`)

```
params := clone(extraParams)
if !parseBoolean(params.allowSignLTSignature): checkLongTermAttributes(sign)      // §8
noticeIncompatibleConfig(algorithm, params)                                      // §2.1
signedData := parse CMSSignedData(sign)  (failure → AOInvalidSignatureFormatException "La firma proporcionada no es CMS/CAdES")
cfg := CAdESParameters.load(data, signedData, algorithm, params)                // data may be null
sd  := SignedData parsed with ASN1InputStream (ContentInfo → [0] → SignedData)

// encapContentInfo
if cfg.contentData != null:                         // implicit mode AND data given (and no precalculated hash)
     encInfo := SEQUENCE { id-data, [0] OCTET STRING data }      // re-embeds content (detached → attached possible)
else:
     encInfo := sd.encapContentInfo (unchanged)
     if cfg.dataDigest == null and encInfo has eContent:
          cfg.dataDigest := H(cfg.digestAlgorithm, eContent)     // eContent cast to DEROctetString:
                                                                  // constructed (BER) OCTET STRING → ClassCastException → AOException 211001
// certificates
certificates := sd.certificates (all existing, in order) ++ every cert of certChain (full chain, no dedup)
                // includeOnlySignningCertificate is ignored; NullPointerException if sd has no certificates

// digest lookup when no data and no embedded content
for each existing SignerInfo si (in parsed order):
     keep si unchanged
     if cfg.dataDigest == null and si.digestAlgorithm.OID == OID(digest(algorithm)):
          cfg.dataDigest := value of si's messageDigest attribute       // first match wins
if cfg.dataDigest == null and cfg.contentData == null: throw ContainsNoDataException (code 510001)

signedAttrs := CAdESUtils.generateSignedAttributes(certChain[0], cfg, false)   // §4.4, DER SET
sig := AOPkcs1Signer.sign(DER(signedAttrs), algorithm, key, certChain, cfg.extraParams)
newSI := SignerInfo { v1, IssuerAndSerial(certChain[0]), SEQ{OID(digest(algorithm)),NULL},
                      signedAttrs, SEQ{OID(compose(digest, certKeyType)),NULL} /* §3.3 */, sig, no unsigned }
output := ContentInfo{ signedData, SignedData{
              digestAlgorithms = sd.digestAlgorithms  (UNCHANGED — new digest algorithm NOT added),
              encInfo, certificates, crls = sd.crls (preserved),
              signerInfos = DER-sorted SET(existing ∪ {newSI}) } }  — DER
```

When data must be provided: only when the signature is detached **and** no existing SignerInfo uses the same digest algorithm OID as the requested algorithm. Providing data for an attached signature is allowed and it is **not** compared with the embedded content.

No timestamp is added on cosign.

### 6.2 CMS cosign (`CoSigner`)

(a) `cosign(data, sign, …)`:
* `encapContentInfo` is **rebuilt** from `data` and `omitContent` (`mode` case-sensitive `explicit` default, or `precalculatedHashAlgorithm` present): with the default explicit mode an **attached signature becomes detached** (embedded content dropped); with implicit the data is (re-)embedded.
* signedAttrs: if no precalculated hash → `contentType(id-data)`, `signingTime(now, always)`, `messageDigest(H(data))`, custom attrs. If precalculated (`messageDigest = data`) → same plus **`serialNumber` attribute** `{2.5.4.5, SET { PrintableString <decimal serial of certChain[0]> }}`.
* certificates := existing ++ full certChain. `crls` **dropped** (set to absent). digestAlgorithms unchanged. signatureAlgorithm per §3.3 (rsaEncryption for RSA).
(b) `cosign(sign, …)`:
* encInfo unchanged. If eContent present → signedAttrs from the content (no serialNumber attr). Else messageDigest taken from the **last** existing SignerInfo whose digest OID matches (loop does not stop) → `generateSignerInfoFromHash` (with the serialNumber attr). Neither → `ContainsNoDataException`.
* certificates, crls, digestAlgorithms as in (a).

### 6.3 CAdES-ASiC-S cosign (`AOCAdESASiCSCoSigner`)

1. `sig := entry "META-INF/signature.p7s"` (missing → `AOInvalidSignatureFormatException`).
2. `(name, data) := first data entry` (§10; name is the base name, directories stripped).
3. `newSig := AOCAdESCoSigner.cosign(data, sig, …)` (params as given → default explicit, digest from data).
4. **Bug**: rebuilds the container with `createSContainer(newSig, data, signatureFilename = name, dataFilename = "META-INF/signature.p7s")` — the arguments are swapped, so the output ZIP stores **the data under `META-INF/signature.p7s` and the signature under the data's name**. Rust parity decision required (recommend fixing and documenting).

---

## 7. Counter-signature (countersign)

### 7.1 Target selection and node numbering

* Nodes = all SignerInfos: top-level `signerInfos` plus every SignerInfo nested in `counterSignature` (1.2.840.113549.1.9.6) unsigned attributes, recursively.
* Leaf = SignerInfo with no counterSignature attribute.
* Numbering (CMS NODES/SIGNERS, and the tree view): **pre-order DFS starting at 0**, top-level signers in their encoded (DER-sorted) order, each followed by its countersignature subtree, children in encoded order.

| Target | CAdES (`AOCAdESCounterSigner`) | CMS (`AOCMSSigner`) | Triphase |
|---|---|---|---|
| `TREE` | every node gets a new countersignature | same | server: every node |
| `LEAFS` | only leaves | only leaves (with quirks) | server: only leaves |
| `NODES` | **rejected**: `AOException` code `600110` ("No se soporta la firma de nodos individuales") | `targets` = `Integer[]` of node indexes; de-duplicated (order preserved, **not sorted**), processed from the last array element to the first | rejected |
| `SIGNERS` | rejected (`600110`) | `targets` = `String[]` CNs; nodes whose `AOUtil.getCN(cert)` equals any target (exact match); indexes sorted ascending, processed from highest to lowest | rejected |
| `null` | defaults to `LEAFS` | returns `null` | `IllegalArgumentException` |

### 7.2 CAdES countersign algorithm (`CAdESCounterSigner`)

```
params := clone(extraParams)
if !parseBoolean(params.allowSignLTSignature): checkLongTermAttributes(sign)          // §8 (top-level only)
cfg := CAdESParameters.load(null, algorithm, params)        // one signingTime for the whole call
reject NODES/SIGNERS; target := targetType ?? LEAFS
sd := parse (ContentInfo → [0] → SignedData)
certificates := sd.certificates ++ full certChain           // no dedup, includeOnlySignningCertificate ignored
newRoots := for each top-level si: process(si)
output := SignedData{ sd.digestAlgorithms (unchanged), sd.encapContentInfo (unchanged),
                      certificates, sd.crls (preserved), DER-SET(newRoots) }  — DER

process(si):
   kept := []        // non-countersignature unsigned attributes, in original order
   children := []    // processed countersignature SignerInfos
   isLeaf := true
   for each unsigned attribute ua of si (if any):
       if !parseBoolean(params.allowSignLTSignature): checkUnsupported(ua.type)     // §8, per node
       if ua.type == 1.2.840.113549.1.9.6:
            isLeaf := false
            for each value v in ua.values that parses as SignerInfo: children += process(v)
            // values that do not parse as SignerInfo are silently dropped
       else: kept += ua
   if target == TREE or (target == LEAFS and isLeaf):
       children += newCounterSignature(si)
   kept += Attribute{ 1.2.840.113549.1.9.6, DER-SET(children) }   // ALWAYS added — all former
                                                                   // counterSignature attributes merged into ONE
   return SignerInfo{ si.sid, si.digestAlgorithm, si.signedAttrs (as parsed), si.signatureAlgorithm,
                      si.signature, DER-SET(kept) }

newCounterSignature(si):
   cfg.contentData := si.signature (OCTET STRING value); cfg.dataDigest := null
   if profile == advanced: cfg.contentTypeOid := "1.2.840.113549.1.7.1"; cfg.contentDescription := null
   if profile == baseline: cfg.contentTypeOid := null; cfg.contentDescription := null
   signedAttrs := generateSignedAttributes(certChain[0], cfg, isCountersign=true)
        // = messageDigest(H(digest(algorithm), si.signature)), signingCertificate(V2), [sigPolicyId],
        //   [contentHints{id-data} — advanced only, even if includeContentHintAttribute=false],
        //   [commitment types], [signerLocation], [signerAttr(V2)], [signingTime]
        //   NO contentType, NO mimeType
   sig := AOPkcs1Signer.sign(DER(signedAttrs), algorithm, key, certChain, cfg.extraParams)
   return SignerInfo{ v1, IssuerAndSerial(certChain[0]), SEQ{OID(digest(algorithm)),NULL}, signedAttrs,
                      SEQ{OID(compose(digest(algorithm), certKeyType)),NULL}, sig, no unsigned attrs }
```

Notes:
* counterSignature value per RFC 5652 §11.4: the countersignature's `messageDigest` is the hash of the target's `signature` octets (the OCTET STRING contents).
* Every rebuilt SignerInfo gets a counterSignature attribute (possibly with an empty SET if a node is neither countersigned nor has countersignatures — cannot happen with TREE/LEAFS).
* Existing unsigned attributes (e.g. `signatureTimeStampToken`) are preserved; the merged counterSignature attribute is appended and then the SET is DER-sorted.
* No timestamp is added.

### 7.3 CMS countersign algorithm (`CounterSigner`)

Countersignature SignerInfo (`generateCounterSignSignedInfo`):
```
SignerInfo { v1, IssuerAndSerial(chain[0]), SEQ{OID(digest(algorithm)),NULL},
  signedAttrs DER-SET {
     signingTime   { 1.2.840.113549.1.9.5, SET { UTCTime now } },
     messageDigest { 1.2.840.113549.1.9.4, SET { OCTET STRING H(target.signature) } },
     serialNumber  { 2.5.4.5, SET { PrintableString <decimal serial of chain[0]> } },   -- non-standard
     <custom addSignedAttribute attrs>
  },
  SEQ{ rsaEncryption | sig OID, NULL }, signature,
  unsignedAttrs: custom addUnsignedAttribute attrs or absent }
```
Container: `certificates := existing ++ certChain[0] only` (unlike cosign); `crls` **dropped**; digestAlgorithms and encapContentInfo unchanged.

Unsigned-attribute rebuilding (TREE, `getCounterUnsignedAtributes`) for each node:
* For each existing unsigned attribute: if it is `signatureTimeStampToken` (1.2.840.113549.1.9.16.2.14) → kept as an attribute; else each value that is a SEQUENCE is **assumed to be a SignerInfo** and recursed (any non-countersignature attribute with SEQUENCE values breaks or gets misinterpreted); non-SEQUENCE values are **dropped**.
* A new countersignature for this node is appended.
* Output: each SignerInfo child becomes **its own** `counterSignature` Attribute with a single-value SET (several Attributes with the same OID), timestamps kept; then DER-sorted. A node with no unsigned attributes gets `SET { counterSignature{ SET{ new } } }` (plus custom unsigned attrs).

LEAFS (`getCounterLeafUnsignedAtributes`): same traversal but a new countersignature is added only when: the node has no unsigned attributes, or its only collected item is a timestamp attribute. Quirks: a node with ≥2 timestamps and no countersignatures is not countersigned; a node whose unsigned attrs yield nothing gets an **empty** counterSignature attribute (then fails validation: "A countersignature attribute MUST contain at least one AttributeValue").

NODES/SIGNERS (`counterNode`): for each target (processed from the end of the array): renumber pre-order from 0; the target node gets its existing children kept as-is plus a new countersignature (one Attribute per child, timestamps kept); nodes before it are rebuilt the same way without new signatures; nodes after are copied. A new SignedData is built after each target and re-parsed.

### 7.4 CAdES-ASiC-S countersign (`AOCAdESASiCSCounterSigner`)
Extract signature + first data entry, `AOCAdESCounterSigner.countersign(sig, …)`, then the **same swapped `createSContainer` call** as §6.3.

---

## 8. Long-term attributes guard (`CAdESMultiUtil`)

Applies to CAdES cosign and countersign (and server triphase cosign/countersign).

Long-term unsigned attribute OIDs: `1.2.840.113549.1.9.16.2.48` (archiveTimestampV2), `0.4.0.1733.2.4` (archive-time-stamp-v3), `0.4.0.1733.2.2` (long-term-validation), `1.2.840.113549.1.9.16.2.27` (archiveTimestamp v1).

* `allowSignLTSignature` absent → if any **top-level** SignerInfo has one of them → `SigningLTSException` (a `RuntimeConfigNeededException`, request type CONFIRM, message code `signingLts`, needed param `allowSignLTSignature`, error `ErrorCode.Functional.SIGNING_LTS`); the UI asks the user and retries with the param.
* `allowSignLTSignature=false` (explicit) → same exception with `denied=true`.
* `allowSignLTSignature=true` → no check.
* Countersign additionally checks every visited node's unsigned attributes (`checkUnsupported`) with the same semantics.
* Input not parseable as CMS → `AOInvalidSignatureFormatException`.

---

## 9. Timestamps (RFC 3161) and CAdES-T

### 9.1 `CMSTimestamper.addTimestamp(pkcs7, hashAlgorithm, time)` (intended CAdES-T mechanism, also used by PAdES)
```
digestAlgorithm := normalize(hashAlgorithm)
signedData := CMSSignedData(pkcs7)             (failure → IllegalArgumentException)
for each TOP-LEVEL SignerInformation si:
    imprint := H(digestAlgorithm, si.signature octets)
    token   := getTimeStampToken(imprint, digestAlgorithm, time)      // DER TimeStampToken ContentInfo
    si'     := replaceUnsignedAttributes(si, { Attribute{1.2.840.113549.1.9.16.2.14, SET{token}} })
               // REPLACES all existing unsigned attributes (countersignatures would be lost)
return CMSSignedData.replaceSigners(signedData, store(si'…)).getEncoded()
    // digestAlgorithms recomputed from the signers (DER SET);
    // getEncoded() is BER: outer ContentInfo/[0]/SignedData use INDEFINITE lengths
```

### 9.2 Request (`getTimeStampToken`)
```
TimeStampReq ::= SEQUENCE {
  version        INTEGER 1
  messageImprint SEQUENCE { SEQUENCE { <OID of digestAlgorithm>, NULL }, OCTET STRING imprint }
  reqPolicy      OID <tsaPolicy, default 0.4.0.2023.1.1>
  nonce          INTEGER <time.getTimeInMillis()>   -- millisecond timestamp, not random
  certReq        BOOLEAN TRUE                         -- omitted when tsaRequireCert=false
  extensions [0] IMPLICIT Extensions                  -- only if tsaExtensionOid + tsaExtensionValueBase64
}
```
(If the digest algorithm were null, SHA-1 `1.3.14.3.2.26` would be used.)

### 9.3 Transport and response handling
* `http`/`https`: POST body = DER request; headers `Content-Type: application/timestamp-query`, `Content-Transfer-Encoding: binary`; Basic auth when `tsaUsr` non-empty; HTTPS: TLS context with optional client keystore (`tsaSslKeyStore*`, KeyManagerFactory default algorithm), trust store or **trust-all**, hostname verification disabled when `verifyHostname=false`. Response body Base64-decoded if the response `Content-Encoding` header equalsIgnoreCase `base64`.
* `socket://host:port`: TCP, timeout 500 000 ms; send `int32 BE (len+1)`, `byte 0x00`, request; read `int32 size`, `byte flag`, `size-1` bytes; flag must be `5` or `6`, else `IOException`.
* Response validation: parse `TimeStampResponse` (fail → `AOException` 211003), `validate(request)` (status granted/grantedWithMods, nonce, imprint, policy, cert presence when requested; fail → 211003), `failInfo != 0` → 211003, missing token → 211003. Connection `IOException` → `AOException` code `410001`.
* Returned token = `TimeStampToken.getEncoded()` (the ContentInfo{signedData} of the TSA).

### 9.4 CAdES-T status in this codebase — dead path
`AOCAdESSigner.applyTimeStamp` instantiates `TsaParams(extraParams)` (if this fails, e.g. no `tsaURL`, it silently returns the signature), then calls
`cmsTimestamperClass.getMethod("getTsaHashAlgorithm")` — that method lives in `TsaParams`, not `CMSTimestamper` → `NoSuchMethodException` → caught → logged SEVERE "No se ha podido aplicar el sello de tiempo" → **the unsigned signature is returned**. Introduced by commit `a01e2403e` (2024-08-13). Therefore:
* In this version CAdES `sign` **never** adds `signatureTimeStampToken`, whatever the `tsa*` params.
* cosign / countersign never call the timestamper at all.
* No archive timestamps / content timestamps / CAdES-C/X/XL/A are generated anywhere.

Parity recommendation: reproduce "no timestamp" by default; if CAdES-T is implemented, follow §9.1–9.3 and prefer DER output (the Java path, if fixed, would emit BER indefinite-length outer wrappers and drop other unsigned attributes).

---

## 10. CAdES-ASiC-S container (`ASiCUtil`, afirma-core)

`createSContainer(signature, data, signatureFilename, dataFilename)` (signature and data must be non-empty, else `IllegalArgumentException`):

| # | Entry name | Content |
|---|---|---|
| 1 | `mimetype` | ASCII `application/vnd.etsi.asic-s+zip` (no newline) |
| 2 | `dataFilename` or `dataobject.<ext>` | the signed data |
| 3 | `signatureFilename` or `META-INF/signature.p7s` | the detached CAdES (DER) |

* ZIP archive comment: `mimetype=application/vnd.etsi.asic-s+zip`.
* Written with `java.util.zip.ZipOutputStream` defaults: **all entries DEFLATED** (including `mimetype`, which ASiC requires to be STORED — non-conformant), data descriptors, UTF-8 names, current time stamps. No `META-INF/manifest.xml` / `ASiCManifest`.
* `<ext>` = `MimeHelper(data).getExtension()`: `xml` for XML, Office/ODF extension from `OfficeAnalizer`, else JMimeMagic extension; generic/unknown → `bin`.
* Inner CAdES: detached (`mode=explicit` forced), all other CAdES params honoured.

Reading:
* `getASiCSBinarySignature(zip)`: content of the first entry named exactly `META-INF/signature.p7s`; none → `IOException`. Input ≥ 1 000 000 000 bytes → `IOException`.
* `getASiCSData(zip)`: map *basename → bytes* of every entry whose full name is not `META-INF/signature.p7s`, `META-INF/signatures.xml` or `mimetype` (directory entries and other META-INF files are counted as data too). Empty → `IOException`. Consumers take `keySet().iterator().next()` of a `HashMap` ("first" = hash order; deterministic only with one data entry).

---

## 11. Triphase split (pre-sign / post-sign)

The client (`AOCAdESTriPhaseSigner`) never builds ASN.1; it exchanges with the server:

1. **Pre-sign** (`op=pre`, `cop=sign|cosign|countersign`, `format=CAdES|CAdES-ASiC-S`, `algo`, `cert`, `doc`, `params=Base64(properties)`).
   Response: Base64 of TriphaseData XML (`<xml><firmas><firma Id=…><param n="…">…</param>…`), or text starting with `ERR-`.
2. Client signs each `PRE` with `AOPkcs1Signer` using `composeSignatureAlgorithmName(algo, key.getAlgorithm())`, adds `PK1` (Base64 signature), removes `PRE` unless `NEED_PRE=true`.
3. **Post-sign** (`op=post`, same params + `session=Base64(TriphaseData)` + `doc`). Response `OK NEWID=<Base64URL result>`.

How the server splits CAdES (`CAdESTriPhasePreProcessor`, `AOCAdESTriPhaseCoSigner`, `AOCAdESTriPhaseCounterSigner`):

| Operation | PRE (to be signed by client) | Server post-sign assembly |
|---|---|---|
| sign | `CAdESTriPhaseSigner.preSign` = DER `SET OF` signed attributes (§4.4, signingTime fixed at pre-sign). TriSign params: `PRE`, `NEED_PRE=true`, `NEED_DATA=true` if implicit. | `CAdESTriPhaseSigner.postSign(algo, implicit ? data : null, certChain, PK1, PRE)` — identical structure to §4.2/4.3 (signatureAlgorithm rule of CAdES sign). Implicit only if param `mode` equalsIgnoreCase `implicit`. No timestamp. |
| cosign | signed attributes built with `CAdESParameters.load(embeddedData, algo, params)` — note: *without* the previous SignedData, so content hints/mime are **not** copied from previous signers (unlike local cosign §6.1): attached → detected from the embedded data; detached → params or `id-data`/`binary`. When detached, messageDigest = first signer with matching digest OID (`ObtainContentSignedData.obtainMessageDigest`), else `ContainsNoDataException`. Optional pre-validation of the existing signature (`checkSignatures`, `ValidateBinarySignature`; first result KO → `InvalidSignatureException`). | New SignerInfo with composed signatureAlgorithm OID (§3.3); certificates = existing ++ chain; digestAlgorithms and crls kept; eContent re-embedded only if the original was attached. |
| countersign | one TriSign per target SignerInfo (TREE: all; LEAFS: leaves), id = Base64(SHA-256(target signature)); PRE = countersignature signed attrs (§7.2 rules, shared date). | Inserts each countersignature into its target (by id). |
| CAdES-ASiC-S | sign only (mode forced explicit); post-sign wraps with `createSContainer(signature, data, "META-INF/signature.p7s", asicsFilename)` (correct argument order). Cosign/countersign → `UnsupportedOperationException`. | |

---

## 12. Reading operations and format detection

### 12.1 Signers tree (`ReadNodesTree.readNodesTree(sign, asSimpleSignInfo)`)

* Parses ContentInfo → `[0]` → SignedData.
* Root node user object: the string `"Datos"`.
* For each top-level SignerInfo in encoded order: reads `sid` as `IssuerAndSerialNumber` (SKI sids break the whole read → caller returns `null`) and finds the certificate in `SignedData.certificates` by **serial number only** (issuer ignored).
  * `asSimpleSignInfo=false`: node = CN string (`AOUtil.getCN`: CN, else OU, else first RDN value; `""` if cert not found).
  * `asSimpleSignInfo=true`: node = `AOSimpleSignInfo([cert], signingTime)` with `pkcs1 = signature`, `signAlgorithm = <digest>with<enc>` where digest ∈ {`SHA1`,`SHA256`,`SHA384`,`SHA512`} (else the OID string) and enc ∈ {`RSA`,`DSA`,`ECDSA`} from the signatureAlgorithm OID (rsaEncryption and sha*WithRSA → `RSA`), else the OID. `signingTime` from the `signingTime` attribute (UTCTime or GeneralizedTime) or null. Cert not found → empty array → constructor throws → whole tree `null`.
* Children: values of unsigned attributes whose type is **not** one of {`…2.14` signatureTimeStampToken, `…2.27` archiveTimestamp, `…2.25` escTimeStamp, `…2.22` revocationRefs, `…2.24` revocationValues, `…2.21` certificateRefs, `…2.23` certValues, `…2.48` archiveTimestampV2, `0.4.0.1733.2.4`, `0.4.0.1733.2.2`} and that are SEQUENCEs are treated as SignerInfos (countersignatures), recursively.
* Timestamps are never reported (`timestampingTime` stays null).

### 12.2 Content extraction (`ObtainContentSignedData`)
* `obtainData(sign)`: parse; if first OID is signedData and eContent present → its octets (cast to DEROctetString: a constructed BER eContent throws `ClassCastException`, uncaught); detached → `null`; non-signedData → `null` (warning); parse errors → `AOInvalidSignatureFormatException`.
* **Implicit vs explicit detection** in AutoFirma is exactly "`getData()` returns non-null vs null".
* `obtainMessageDigest(sign, digestAlg)`: first top-level SignerInfo whose digest OID matches → its messageDigest; else null.

### 12.3 `isSign` predicates

| Predicate | Algorithm |
|---|---|
| `CAdESValidator.isCAdESSignedData(data, enforceCAdES)` | Parse a SEQUENCE; 1st element must be OID `1.2.840.113549.1.7.2`; 2nd a tagged object containing SignedData. If `enforceCAdES`: **every** SignerInfo must have a signed attribute `signingCertificate` (…2.12) or `signingCertificateV2` (…2.47) (zero SignerInfos → true). Any exception (incl. SignerInfo without signedAttrs) → false. |
| `CAdESValidator.isCAdESValid(data, enforce)` | true if the blob is ContentInfo of type Data, SignedData (as above), DigestedData, EncryptedData, EnvelopedData or SignedAndEnvelopedData. Note: `isCAdESData` is not exception-guarded — garbage input may throw `IOException`/`ClassCastException` to the caller. |
| `ValidateCMSSignedData.isCMSSignedData(data)` | Same parse; true unless some SignerInfo has `sigPolicyId` (…2.15) in its signed attributes; any exception (incl. no signedAttrs) → false. So CAdES-BES without policy is also "CMS". |
| `AOCAdESASiCSSigner.isSign` | **Bug, always false**: it extracts the inner signature and then calls `new AOCAdESASiCSSigner().isSign(sig)`, which tries to read the CMS bytes as a ZIP again. ASiC-S is never auto-detected. |
| `SignatureFormatDetectorPadesCades.isASN1Format(sig)` | `new CMSSignedData(sig)` parses and `getSignedContent().getContentType()` succeeds (throws on detached → false) and content type ≠ signedData. |

### 12.4 MIME / OID helpers (`MimeHelper`, `OfficeAnalizer`, `resources/mimetypes_oids.properties`)

OID ↔ MIME table (bidirectional; unknown MIME → `1.2.840.113549.1.7.1`; unknown OID → `application/octet-stream`; null MIME → id-data; null OID → octet-stream):

| OID | MIME |
|---|---|
| `1.2.840.113549.1.7.1` | `data` (sic) |
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

Detection (`new MimeHelper(data)`):
1. JMimeMagic (`afirma-lib-jmimemagic` 0.0.10, `magic.xml`, loaded by reflection; optional) → mime, extension, description (`"???"` → null).
2. `getMimeType()`: if null or `text/xml` → `text/xml` iff `AOFileUtils.isXML(data)` else null; if `application/zip` or `application/msword` → `OfficeAnalizer.getMimeType(data)` (ODF `mimetype` entry, OOXML `[Content_Types].xml`, Office-97 string sniffing: "Microsoft Excel"→xls, "Microsoft Office Word"→doc, "Microsoft Office PowerPoint"→ppt, "Microsoft Project"→mpp, "Microsoft Visio"→vnd.visio; fallbacks `application/zip` or the misspelled `application/octect-stream`); null → `application/octet-stream`.
3. `getDescription()`: `text/xml` → `Documento XML`; Office/ODF/zip → Spanish descriptions (`Documento de texto`, `Presentación`, `Hoja de cálculo`, `Gráfico`, `Diagrama`, `Fórmula`, `Base de datos`, `Imagen`, `Plantilla de documento`, `Archivo zip`, `Planificaci&oacute;n de proyecto` (sic, HTML entity)); else the JMimeMagic description; else `binary`.

Exact reproduction of `contentHints.contentDescription` for non-XML/non-Office content requires porting JMimeMagic's matcher and `magic.xml` (e.g. PDF top-level description `PDF document`, JPEG `JPEG image data`, PNG `PNG image data,`, GIF `GIF image data`); this belongs to the core MIME-detection spec.

---

## 13. Validation (`afirma-crypto-validation`)

### 13.1 Entry points
* `SignValiderFactory.getSignValider(bytes)`: PDF → PDF validator; FacturaE/XML → XML validator; OOXML/ODF → `null`; **everything else → `ValidateBinarySignature`**. `getSignValider(signer)`: `AOCAdESSigner` → binary (AOCMSSigner is not mapped).
* `ValidateBinarySignature.validate(sign)` = `validate(sign, data=null, checkCertificates=true)`; `validate(sign, boolean)`; `validate(sign, Properties)` (params ignored); static `validate(sign, data[, checkCertificates])`.

### 13.2 Algorithm
```
list := []
signer := AOCAdESSigner if its isSign(sign) else AOCMSSigner if its isSign(sign)
          else return [KO NO_SIGN]
signedData := data ?? signer.getData(sign)
   null → list += UNKNOWN NO_DATA        ("detached without data")
   AOInvalidSignatureFormatException → list += KO NO_SIGN
   other AOException → list += KO UNKOWN_ERROR
try:
   s := data == null ? CMSSignedData(sign) : CMSSignedData(CMSProcessableByteArray(data), sign)
   signWithData := s.signedContent != null
   for each TOP-LEVEL SignerInformation si (countersignatures are NOT verified):
       profile := SignatureFormatDetectorPadesCades.resolveASN1Format(s, si)        // §13.3
       results := verifySign(si, certs, checkCertificates, profile, signWithData)
       UNKNOWN results inserted at list index 0, others appended
catch CMSSignerDigestMismatchException → KO NO_MATCH_DATA; other Exception → KO (error null)
list := checkValidityKOPriority(list)        // remove identical objects; each KO moved to the front (last KO first)
list := checkLongStandingValiditySign(list)  // if the only KO kind is CERTIFICATE_EXPIRED and a
                                             // SIGN_PROFILE_NOT_CHECKED exists → swap it to position 0
return list
```
`verifySign(si, …)`:
1. Certificate = first certificate in the SignedData store with **the same serial number** as `si.sid` (issuer ignored). None → exception → `KO CANT_VALIDATE_CERT`.
2. If `checkCertificates`: `X509Certificate.checkValidity()` at **current time** → `KO CERTIFICATE_EXPIRED` / `KO CERTIFICATE_NOT_VALID_YET`.
3. Bouncy Castle `SignerInformation.verify(verifier built from the cert)`, which in order:
   * if signingTime present: certificate must be valid at signingTime, else exception (→ `KO CANT_VALIDATE_CERT`);
   * digest of content (or of nothing when detached without data) and signed attributes fed to the verifier;
   * contentType attribute must be present (non-countersignature with signedAttrs) and equal eContentType;
   * cmsAlgorithmProtect checks if present;
   * **messageDigest must match** → else `CMSSignerDigestMismatchException`: reported as `KO NO_MATCH_DATA` only when content is available; **silently ignored for detached signatures without data — and because the mismatch is raised before the signature check, the PKCS#1 value is then never verified**;
   * no counterSignature in signedAttrs; each counterSignature unsigned attribute must have ≥ 1 value (else exception → KO);
   * cryptographic signature check (false → "Firma no valida" → `KO CANT_VALIDATE_CERT`).
4. If `profile` ∉ {`CAdES-BES`, `No reconocido`, `CAdES B-Level`, `CAdES B-B-Level`, `CMS`, `CAdES-EPES`} → add `UNKNOWN SIGN_PROFILE_NOT_CHECKED` (e.g. `CAdES-T`, `CAdES T-Level`, `CMS-T`, LT/LTA).
5. No results → `OK`.

Detail types: `OK`, `KO`, `UNKNOWN`, `PENDING_CONFIRM_BY_USER`, `GENERATED`. Messages (`validationmessages_es_ES` / `_en_US`): OK/GENERATED → "Firma válida"; UNKNOWN → "Validación incompleta"; PENDING → "Validez a confirmar por el usuario"; KO → "Firma no válida"; `toString()` = type text + `": "` + error text. Error texts (es): NO_DATA "no se puede comprobar la validez por no tener los datos firmados"; CORRUPTED_SIGN "la informaci&oacute;n contenida en la firma no es consistente (certificados corruptos, etc.)"; NO_MATCH_DATA "la firma no se corresponde con los datos firmados"; NO_SIGN "no se encuentra la firma dentro del documento"; CERTIFICATE_PROBLEM "no se puede extraer un certificado o este no es v&aacute;lido"; CERTIFICATE_EXPIRED "existe un certificado de firma caducado"; CERTIFICATE_NOT_VALID_YET "existe un certificado de firma que aun no es v&aacute;lido"; CANT_VALIDATE_CERT "no se ha podido validar el certificado correctamente"; ALGORITHM_NOT_SUPPORTED "la firma contiene un algoritmo no reconocido o no soportado"; UNKOWN_ERROR "no se puede comprobar la validez de la firma"; SIGN_PROFILE_NOT_CHECKED "la firma contiene atributos longevos que Autofirma no puede validar. Para una validaci&oacute;n completa recurra a VALIDe." (full list keys `SignValidationMessage.0`–`.27`). `InvalidSignatureException` uses error code `500002`.

### 13.3 ASN.1 profile detection (`resolveASN1Format(signedData, signerInformation)`)
```
isCMS        := no signingCertificate, signingCertificateV2, otherSigCert (…2.19)
isEPES       := has sigPolicyId (…2.15)
isBES        := has any of signingCertificate / V2 / otherSigCert
isBB         := has signingCertificateV2
isBLevel     := has signingTime
isT          := unsigned signatureTimeStampToken (…2.14)
isLT         := none of {…2.21, …2.22, …2.44, …2.45, …2.25, …2.26, …2.23, …2.24, …2.27, …2.48, 0.4.0.1733.2.2}
                in unsigned attrs AND SignedData.crls non-empty
isLTA        := unsigned 0.4.0.1733.2.4

if isCMS:
    f := "CMS";  if isT: f := "CMS-T"
elif isEPES:
    f := "CAdES-EPES"
    if isBLevel:
        f := "CAdES B-Level"
        if isT:  { f := "CAdES T-Level"; if isLT: { f := "CAdES LT-Level"; if isLTA: f := "CAdES LTA-Level" } }
    elif isT: f := "CAdES-T"
elif isBES:
    f := "CAdES-BES"
    if isBLevel:
        f := "CAdES B-Level"
        if isT:  { f := "CAdES T-Level"; if isLT: { f := "CAdES LT-Level"; if isLTA: f := "CAdES LTA-Level" } }
    -- a BES without signingTime stays "CAdES-BES" even if timestamped
elif isBB: ... (unreachable: isBES already covers signingCertificateV2)
else: "No reconocido"
any exception → "No reconocido"
```
AutoFirma-generated CAdES (always signingTime + signingCertificate) classify as `CAdES B-Level`.

---

## 14. Spanish defaults, hard-coded values and gotchas

### 14.1 Defaults and hard-coded values
* AGE signature policy (via `expPolicy`): see §2.3. `FirmaAGE` = v1.9, OID `2.16.724.1.3.1.1.2.1.9`, SHA-1 hash `G7roucf600+f03r/o0bAOQ6WAs0=`, URL `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf`; forces `profile=advanced`, `mode=implicit` when data < 1 MiB.
* Desktop app defaults (`preferences.properties`): `cadesImplicitMode = true` (desktop CAdES is attached by default, the library default is explicit), no CAdES policy, `signatureHashAlgorithm = SHA256`, `cadesMultisign = cosign`. Desktop passes only policy params and `mode` for CAdES.
* Library defaults: CAdES/CMS `mode=explicit`; CMS algorithm `SHA512withRSA`; content hints `id-data`/`binary`; mime `application/octet-stream`; TSA policy `0.4.0.2023.1.1`, TSA hash SHA-512; policy hash download algorithm SHA-512.
* `AOSignConstants.DEFAULT_OID_TO_SIGN = 1.3.6.1.4.1.1466.115.121.1.40` exists but is unused by CMS/CAdES.

### 14.2 Gotchas (numbered for cross-reference)
* **G1** CAdES-T is dead code (§9.4): `tsa*` params have no effect on CAdES.
* **G2** CAdES-ASiC-S `isSign` always false (§12.3) → never auto-detected.
* **G3** CAdES-ASiC-S cosign/countersign swap entry names (§6.3).
* **G4** ASiC `mimetype` entry is DEFLATED and there is a ZIP comment `mimetype=…`.
* **G5** SignerInfo signatureAlgorithm: rsaEncryption in sign (CAdES & CMS) but `shaNNNWithRSAEncryption` in CAdES cosign/countersign; NULL parameters always, even for ECDSA.
* **G6** digestAlgorithms is never updated on cosign/countersign (CAdES, CMS, triphase).
* **G7** Certificates: sign honours `includeOnlySignningCertificate`; CAdES cosign/countersign and CMS cosign append the full chain; CMS countersign appends only the signer cert; duplicates are not removed; output order is DER-sorted.
* **G8** CRLs preserved by CAdES multi-sign, **dropped** by CMS cosign/countersign.
* **G9** Commitment type loop runs `0..N` inclusive; qualifiers are bare OIDs.
* **G10** `signatureProductionPostalCode` = multi-line postal address (split on `\n`, ≤ 6 lines); province unsupported; empty strings emitted.
* **G11** signingTime always UTCTime with seconds (no GeneralizedTime after 2049).
* **G12** Policy identifier must be an OID; `urn:oid:` prefix stripped & lower-cased; hash-algorithm names must be in the §3.1 list (`urn:oid:…` form fails, contrary to the Javadoc example in `AOCAdESSigner`).
* **G13** `precalculatedHashAlgorithm` (CAdES): messageDigest/signing-cert hash use the precalculated algorithm, but SignerInfo/SignedData digestAlgorithm use the signature algorithm's digest → mismatched, unverifiable signature if they differ. CMS ignores the value entirely.
* **G14** CAdES cosign without data relies on an existing signer with the *same* digest OID; BER-constructed eContent makes cosign/getData fail.
* **G15** CAdES cosign with `mode=implicit` + data turns a detached signature into an attached one; CMS cosign with data and default mode turns an attached signature into a detached one.
* **G16** CMS countersignatures (and CMS cosign-from-hash) contain a non-standard signed attribute `serialNumber` (2.5.4.5, PrintableString decimal).
* **G17** CMS countersign quirks: one counterSignature Attribute per countersignature, unknown non-SEQUENCE unsigned values dropped, possible empty counterSignature attribute in LEAFS, NODES targets processed in reverse array order without sorting (unsorted input shifts indexes), `null` target returns `null`.
* **G18** Validation does not verify countersignatures, matches certificates by serial number only, and does not verify the signature value of detached signatures validated without data.
* **G19** `profile=baseline` is case-sensitive in `CAdESParameters`.
* **G20** SHA-3, SHA-224 (no reliable digest name), RIPEMD-160, MD5, RSA-PSS, EdDSA are not usable; CAdES explicitly rejects `MD*`.
* **G21** contentHints description depends on JMimeMagic; mime derived from the id-data OID is the literal `data`; Office fallback MIME is misspelled `application/octect-stream`.
* **G22** All multi-sign operations re-encode the full input in DER (re-sorting SETs).
* **G23** `AOCAdESASiCSSigner.sign` mutates the caller's Properties (`mode=explicit`).
* **G24** Signers tree fails entirely (returns `null`) if any signer certificate is missing from `certificates` or a sid is SKI-based.
* **G25** CMS `mode` check is case-sensitive; CAdES `mode` check is case-insensitive; in both any value other than "explicit" means implicit.
* **G26** Advanced-profile countersignatures always carry `contentHints{id-data}` (no description), even with `includeContentHintAttribute=false`; baseline countersignatures carry none.
* **G27** The SignerInfo signatureAlgorithm of CAdES sign is derived from the *requested* algorithm string while the value is produced with the *key's* type; callers must pass a key-consistent name.
* **G28** `isCMSSignedData` is also true for CAdES-BES without policy; detection order (CAdES first) matters.
* **G29** TSA HTTPS without trust store trusts every server certificate; TSA nonce is the current time in ms.

---

## 15. Parity checklist

| Feature | Java class(es) | Notes |
|---|---|---|
| Format strings / factory detection order | `AOSignConstants`, `AOSignerFactory` | §1.2 |
| CAdES sign entry checks | `AOCAdESSigner.sign/checkAlgorithm/noticeIncompatibleConfig` | MD* rejection 600107, param purge |
| CAdES parameter resolution | `CAdESParameters.load` | §4.7 exact procedure |
| Policy object | `AdESPolicy`, `AdESPolicyPropertiesManager`, `ExtraParamsProcessor`, `policy.properties` | §2.3, §4.4.5 |
| Signed attributes | `CAdESUtils.generateSignedAttributes` | §4.4 (all encodings) |
| SigningCertificate v1/v2 | `CAdESUtils.getSigningCertificateV1/V2` | SHA-256 default-omission, issuerSerial, cert policies |
| Commitment types | `CommitmentTypeIndicationsHelper` | 0..N loop, bare-OID qualifiers |
| Signer location | `CAdESSignerMetadataHelper`, `CAdESSignerMetadata` | §4.4.7 |
| Claimed roles | `CAdESUtils.getSignerClaimedRoles`, `CAdESAttributes` | signerAttr vs signerAttrV2 |
| Content hints / mimeType | `CAdESParameters`, `MimeHelper`, `OfficeAnalizer`, `mimetypes_oids.properties` | §4.7, §12.4 |
| Pre-sign (DER SET OF attrs) | `CAdESTriPhaseSigner.preSign` | |
| PKCS#1/ECDSA generation + self-verification | `AOPkcs1Signer` | §3.4 |
| SignedData assembly | `CAdESTriPhaseSigner.postSign`, `SigUtils` | §4.2, §4.3 |
| DER SET sorting / re-encoding | SpongyCastle `ASN1Set`, `DEROutputStream` | §4.6 |
| Algorithm names/OIDs | `AOSignConstants.getDigestAlgorithmName`, `composeSignatureAlgorithmName`, `AOAlgorithmID` | §3 |
| CMS sign | `AOCMSSigner`, `GenSignedData`, `CmsUtil` | §5 |
| CAdES cosign | `AOCAdESCoSigner`, `CAdESCoSigner`, `CAdESMultiUtil.addCertificates` | §6.1 |
| CMS cosign | `CoSigner` | §6.2 |
| CAdES countersign | `AOCAdESCounterSigner`, `CAdESCounterSigner` | §7.2 |
| CMS countersign | `CounterSigner`, `ReadNodesTree.readNodesFromSigners/simplyArray` | §7.3 |
| LTS guard | `CAdESMultiUtil.checkLongTermAttributes/checkUnsupported`, `SigningLTSException` | §8 |
| TSA client | `CMSTimestamper`, `TsaParams`, `TsaRequestExtension` | §9 (unused by CAdES in this version) |
| CAdES-T application | `AOCAdESSigner.applyTimeStamp` | dead (G1) |
| ASiC-S container | `ASiCUtil`, `AOCAdESASiCSSigner`, `AOCAdESASiCSCoSigner`, `AOCAdESASiCSCounterSigner` | §10, G2–G4 |
| Triphase client | `AOCAdESTriPhaseSigner`, `PreSigner`, `PostSigner`, `TriphaseDataSigner`, `TriphaseUtil` | §11 |
| Triphase server split | `CAdESTriPhasePreProcessor`, `CAdESASiCSTriPhasePreProcessor`, `AOCAdESTriPhaseCoSigner`, `AOCAdESTriPhaseCounterSigner` | §11 |
| Signers tree | `ReadNodesTree` | §12.1 |
| getData / implicit-explicit | `ObtainContentSignedData` | §12.2 |
| isSign predicates | `CAdESValidator`, `ValidateCMSSignedData` | §12.3 |
| Validation | `ValidateBinarySignature`, `SignValider`, `SignValidity`, `ValidationMessages`, `CertHolderBySignerIdSelector` | §13.2 |
| Profile detection | `SignatureFormatDetectorPadesCades.resolveASN1Format`, `ISignatureFormatDetector` | §13.3 |
| Error codes | `BinaryErrorCode` (211001 unknown, 211002 internal, 211003 TSA, 510001 no data, 300001 SC version), `ErrorCode` (600107, 600110, 200110–200114, 214001, 410001, 500002) | |

Source files (absolute):
`/home/octo/Projects/autofirma/afirma-crypto-cades/src/main/java/es/gob/afirma/signers/cades/` (`AOCAdESSigner`, `CAdESParameters`, `CAdESUtils`, `CAdESTriPhaseSigner`, `GenCAdESEPESSignedData`, `CAdESExtraParams`, `CAdESValidator`, `CommitmentTypeIndicationsHelper`, `CAdESSignerMetadataHelper`, `AOSigPolicyQualifierInfo`, `CAdESAttributes`, `asic/AOCAdESASiCSSigner`),
`/home/octo/Projects/autofirma/afirma-crypto-cades-multi/src/main/java/es/gob/afirma/signers/multi/cades/`,
`/home/octo/Projects/autofirma/afirma-crypto-cms/src/main/java/es/gob/afirma/signers/cms/`,
`/home/octo/Projects/autofirma/afirma-crypto-core-pkcs7/src/main/java/es/gob/afirma/signers/pkcs7/`,
`/home/octo/Projects/autofirma/afirma-crypto-core-pkcs7-tsp/src/main/java/es/gob/afirma/signers/tsp/pkcs7/`,
`/home/octo/Projects/autofirma/afirma-crypto-cadestri-client/src/main/java/es/gob/afirma/signers/cadestri/client/`,
`/home/octo/Projects/autofirma/afirma-crypto-validation/src/main/java/es/gob/afirma/signvalidation/`,
`/home/octo/Projects/autofirma/afirma-core/src/main/java/es/gob/afirma/core/signers/` (`AOSignConstants`, `AdESPolicy`, `AdESPolicyPropertiesManager`, `ExtraParamsProcessor`, `AOPkcs1Signer`, `AOSignerFactory`, `asic/ASiCUtil`),
`/home/octo/Projects/autofirma/afirma-core/src/main/resources/policy.properties`,
`/home/octo/Projects/autofirma/afirma-core/src/main/resources/resources/mimetypes_oids.properties`,
`/home/octo/Projects/autofirma/afirma-server-triphase-signer-core/src/main/java/es/gob/afirma/triphase/signer/`.

---

## 16. Appendices

### 16.1 OID quick reference

| Name | OID |
|---|---|
| id-data | 1.2.840.113549.1.7.1 |
| id-signedData | 1.2.840.113549.1.7.2 |
| id-digestedData / envelopedData / signedAndEnvelopedData / encryptedData | 1.2.840.113549.1.7.5 / .7.3 / .7.4 / .7.6 |
| contentType | 1.2.840.113549.1.9.3 |
| messageDigest | 1.2.840.113549.1.9.4 |
| signingTime | 1.2.840.113549.1.9.5 |
| counterSignature | 1.2.840.113549.1.9.6 |
| id-aa-contentHint | 1.2.840.113549.1.9.16.2.4 |
| id-aa-signingCertificate | 1.2.840.113549.1.9.16.2.12 |
| id-aa-signatureTimeStampToken | 1.2.840.113549.1.9.16.2.14 |
| id-aa-ets-sigPolicyId | 1.2.840.113549.1.9.16.2.15 |
| id-aa-ets-commitmentType | 1.2.840.113549.1.9.16.2.16 |
| id-aa-ets-signerLocation | 1.2.840.113549.1.9.16.2.17 |
| id-aa-ets-signerAttr | 1.2.840.113549.1.9.16.2.18 |
| id-aa-ets-otherSigCert | 1.2.840.113549.1.9.16.2.19 |
| certificateRefs / revocationRefs / certValues / revocationValues | 1.2.840.113549.1.9.16.2.21 / .22 / .23 / .24 |
| escTimeStamp / certCRLTimestamp / archiveTimestamp | 1.2.840.113549.1.9.16.2.25 / .26 / .27 |
| attribute-cert-refs / attribute-revocation-refs | 1.2.840.113549.1.9.16.2.44 / .45 |
| id-aa-signingCertificateV2 | 1.2.840.113549.1.9.16.2.47 |
| archiveTimestampV2 | 1.2.840.113549.1.9.16.2.48 |
| id-spq-ets-uri | 1.2.840.113549.1.9.16.5.1 |
| id-cti-ets-proofOf{Origin,Receipt,Delivery,Sender,Approval,Creation} | 1.2.840.113549.1.9.16.6.{1..6} |
| id-aa-ets-mimeType | 0.4.0.1733.2.1 |
| long-term-validation | 0.4.0.1733.2.2 |
| archive-time-stamp-v3 | 0.4.0.1733.2.4 |
| id-aa-ets-signerAttrV2 | 0.4.0.19122.1.1 |
| id-at-role | 2.5.4.72 |
| id-at-serialNumber (CMS quirk) | 2.5.4.5 |
| certificatePolicies extension | 2.5.29.32 |
| AGE policy v1.9 / v1.8 | 2.16.724.1.3.1.1.2.1.9 / 2.16.724.1.3.1.1.2.1.8 |
| Default TSA policy | 0.4.0.2023.1.1 |

### 16.2 Worked example: emitted attribute order (CAdES-BES, SHA256withRSA, implicit, defaults)

Encoded sizes determine the order (second byte = length):

| Attribute | Encoding start | Total length |
|---|---|---|
| contentType | `30 18 06 09 2A864886F70D010903 31 0B 06 09 2A864886F70D010701` | 26 |
| signingTime | `30 1C 06 09 2A864886F70D010905 31 0F 17 0D <13 ASCII chars>` | 30 |
| contentHints (`"binary"`) | `30 24 06 0B 2A864886F70D0109100204 31 15 30 13 0C 06 "binary" 06 09 …0701` | 38 |
| messageDigest (32-byte hash) | `30 2F 06 09 2A864886F70D010904 31 22 04 20 <hash>` | 49 |
| signingCertificateV2 | `30 81 …` / `30 82 …` (long form) | > 127 |

Emitted order: contentType, signingTime, contentHints, messageDigest, signingCertificateV2. With SHA-1 the messageDigest (`30 23`) sorts before contentHints (`30 24`) — matching fixture `cades_implicit.csig` (contentType, signingTime, messageDigest, contentHint, signingCertificate). Long-form attributes (`30 81`, `30 82`) sort after all short ones, then among themselves by subsequent bytes.

### 16.3 Fixtures useful for parity tests

* `afirma-crypto-cades/src/test/resources/`: `cades_implicit.csig` (SHA-1, attached, SigningCertificate v1), `cades_explicit.csig` (SHA-1, detached, 2 certs), `cades_claimed_role.csig` (SHA-512, signerAttr with two roles, SigningCertificateV2 with `SEQUENCE{sha512, NULL}`, issuerSerial and copied certificate policies), `firma_inc71506.csig`, `ASIC-13576272396538796.zip`, test PKCS#12 keystores (`PFActivoFirSHA256.pfx`, `ANF_PF_Activo.pfx`, …).
* `afirma-crypto-cades-multi/src/test/resources/`: `firma_implicita.csig`, `firma_explicita.csig`, `contrafirma_implicita.csig`, `contrafirma_explicita.csig`, `cades_3nodos.csig`, `cms_implicit.csig`, `CADES-T.csig`, `189027_CAdES-T.csig`, `cadesA.csig`, `cadesPrimeraFirmaConUpgradeArchivo.csig`, `firma_contentType_TIFF.csig`.
* `afirma-crypto-core-pkcs7/src/test/resources/`: `cades-t.csig`, `cades-a.csig`, `countersign-cades.csig`.
