# 03 - XML-based signature formats (XAdES, XMLdSig, FacturaE, ASiC-S XAdES, ODF, OOXML)

Implementation spec for a 1:1 Rust reimplementation of the AutoFirma ("Cliente @firma", v1.9.1) XML signers.
It is written so that the Java code does not need to be read. Everything here was derived from the Java
sources in this repository (HEAD `0d7f3cf01`), from the sources of the external library
`es.uji.crypto.xades:jxades:0.2.2` (downloaded from Maven Central, `jxades-0.2.2-sources.jar`), from the
signed samples under `src/test/resources`, and from the XMLDSig / XAdES standards.

Verification: the XAdES (incl. FacturaE and ASiC-S), XMLdSig and ODF behaviour was confirmed by
compiling the real module sources (afirma-core, core-xml, core-pkcs7(-tsp), xades, xmlsignature, odf)
with JDK 21 against jxades 0.2.2, Apache Santuario (xmlsec) 3.0.5, SpongyCastle 1.58.0.0 and XOM 1.2.10
from Maven Central, running the signers on the repository test keystores and validating every output
with a JSR-105 validator; the examples in sections 6, 7 and 13 are that real output. OOXML (needs an AWT
screen) and the XAdES-T timestamp (needs a TSA) are derived from code only.

Normative language: "MUST" = needed for interoperability or byte/behaviour parity; "quirk" = observed
Java behaviour that is odd or non-standard but that a 1:1 port must reproduce (or consciously decide not
to); "edge" = rare path, low priority.

## Table of contents

1. Scope, modules and external libraries
2. Shared XML infrastructure (`afirma-crypto-core-xml`): parsing, serialization, URIs, algorithms,
   canonicalization, transforms, dereferencing, stylesheets, Base64
3. XAdES signer (`AOXAdESSigner`): API, every extraParam, exact XML per format, QualifyingProperties,
   KeyInfo, ids, manifest, externally detached, XAdES-T timestamp, cosign, countersign, signers
   structure, detection helpers, getData
4. FacturaE signer (`AOFacturaESigner`)
5. ASiC-S XAdES signer (`AOXAdESASiCSSigner`)
6. XMLdSig signer (`AOXMLDSigSigner`)
7. ODF signer (`AOODFSigner`)
8. OOXML signer (`AOOOXMLSigner`)
9. XML signature validation (`afirma-crypto-validation`)
10. Tri-phase (pre/post) split for XAdES
11. Constants and core API (`afirma-core`)
12. Test resources inventory and repository samples
13. Complete examples (XAdES family, real output)
14. Parity checklist
15. Gotchas summary

---

## 1. Scope, modules and external libraries

| Module | Main classes | Role |
|---|---|---|
| `afirma-crypto-core-xml` | `Utils`, `XMLConstants`, `XmlDSigProviderHelper`, `dereference.CustomUriDereferencer`, `style.XmlStyle` | Shared XML helpers used by XAdES and XMLdSig |
| `afirma-crypto-xades` | `AOXAdESSigner`, `XAdESSigner`, `XAdESCoSigner`, `XAdESCounterSigner`, `XAdESUtil`, `XAdESCommonMetadataUtil`, `XAdESTspUtil`, `AOXMLAdvancedSignature`, `EscapeHelper`, `AOFacturaESigner`, `asic.AOXAdESASiCSSigner` | XAdES (BES/EPES and EN 319 132 B-Level), FacturaE, ASiC-S |
| `afirma-crypto-xmlsignature` | `AOXMLDSigSigner` | Plain XMLDSig |
| `afirma-crypto-odf` | `AOODFSigner` | OpenDocument (`META-INF/documentsignatures.xml`) |
| `afirma-crypto-ooxml` | `AOOOXMLSigner`, `OOXMLXAdESSigner`, `relprovider.RelationshipTransformService` | Office Open XML (`_xmlsignatures/`) |
| `afirma-crypto-xadestri-client` | `AOXAdESTriPhaseSigner`, `AOFacturaETriPhaseSigner`, `asic.AOXAdESASiCSTriPhaseSigner` | Tri-phase client (server does the XML) |
| `afirma-crypto-validation` | `ValidateXMLSignature`, `SignatureFormatDetectorXades` | Validation and XAdES level detection |
| `afirma-core` | `AOSignConstants`, `AOSigner`, `AdESPolicy`, `MimeHelper`, `ASiCUtil`, `SecureXmlBuilder` | Constants, interfaces |

External libraries the Rust port must replace:

* **Apache Santuario / JSR-105 (`javax.xml.crypto.dsig`)** - builds `ds:Signature` DOM, computes
  references and SignatureValue, implements C14N and transforms. The provider is forced to
  `org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI` (first in the provider list).
* **jxades 0.2.2** (`es.uji.crypto.xades.jxades`) - builds `xades:QualifyingProperties`. Its behaviour is
  fully documented in section 3 (all relevant classes were read: `XMLAdvancedSignature`, `XAdES`,
  `BasicXAdESImpl`, `ExplicitPolicyXAdESImpl`, `BLevelXAdESImpl`, `QualifyingProperties`,
  `SignedProperties`, `SignedSignatureProperties`, `SigningTime`, `SigningCertificate(V2)Details`,
  `SigningCertificate(V2)Impl`, `SignaturePolicyIdentifierImpl/Details`,
  `SignatureProductionPlace(V2)Details`, `SignerRole(V2)Details`, `DataObjectFormatDetails`,
  `ObjectIdentifierDetails`, `CommitmentTypeIndicationDetails`, `CommitmentTypeIdDetails`,
  `util.ISO8601DateFormat`, `util.Base64`).
* **XOM 1.2.10** (`nu.xom.canonical.Canonicalizer`) - only to canonicalize `ds:SignatureValue` for the
  XAdES-T timestamp imprint.
* **JMimeMagic** (via `MimeHelper`) - MIME sniffing when `mimeType` is not given (see section 11).

---

## 2. Shared XML infrastructure (`afirma-crypto-core-xml` + relevant `afirma-core` helpers)

### 2.1 Parsing

* `Utils.getNewDocumentBuilder()`: namespace-aware, non-validating DOM builder with
  `FEATURE_SECURE_PROCESSING=true` and `ACCESS_EXTERNAL_DTD/SCHEMA/STYLESHEET=""`. It does **not** forbid
  DOCTYPE (internal subsets are processed), but a reference to an external DTD makes parsing fail
  (external access denied). Used to parse signatures and
  XML data in XAdES/XMLdSig.
* `SecureXmlBuilder.getSecureDocumentBuilder()` / `getSecureSAXParser()` (afirma-core): same plus
  `http://apache.org/xml/features/disallow-doctype-decl=true` and external entities disabled.
* `AOFileUtils.isXML(data)` = "a secure SAX parse of the bytes succeeds". **Because DOCTYPE is
  disallowed, any XML containing a `<!DOCTYPE` is classified as NOT XML** (quirk introduced by commit
  `3463f1337`). Consequences in XAdES: such input is base64-embedded in Enveloping/Detached and rejected
  in Enveloped.
* Ids: elements are looked up by an attribute whose **name** equals `Id` **case-insensitively** (`Id`,
  `ID`, `id`), first match in document order (`CustomUriDereferencer.getElementById`). XML-Schema ID
  typing is never used. XAdES-internal lookups (`XAdESUtil.findElementById`) use exactly `Id`.

### 2.2 Serialization (`Utils.writeXML(node, props, styleHref, styleType)`)

* Uses DOM Level 3 `LSSerializer` with parameter `namespaces=false` (no namespace fix-up: whatever
  `xmlns:*` attributes exist in the DOM are written, nothing is added).
* Output encoding = `props[ENCODING]` if present, else `UTF-8`. For XAdES `props[ENCODING]` is
  `outputXmlEncoding` if given, else the `encoding` of the input XML declaration (only when the input
  was XML). `VERSION`/`DOCTYPE_SYSTEM` are collected but ignored by the serializer (DOCTYPE is lost).
* An XML declaration is always written: `<?xml version="1.0" encoding="UTF-8"?>`. Recent JREs write
  the root element immediately after it (no line break); older outputs (<= 2017 samples) had `\n`.
* No pretty printing: `ds:Signature` is produced without any whitespace text nodes; whitespace inside the
  user's own XML content is preserved.
* Attribute order (cosmetic, not covered by signatures because C14N re-sorts): the DOM keeps
  attributes sorted by qualified name (Xerces `AttributeMap`, UTF-16 code-unit order), and the current
  JRE serializer writes a namespace declaration for the element's **own prefix that is not yet in
  scope** first, then all remaining attributes (including other `xmlns:*`) in that sorted order.
  Observed current output: `<ds:Signature xmlns:ds="..." Id="...">` (but `<ds:Signature Id="..."
  xmlns:ds="...">` when an ancestor already declares `ds`, e.g. a FacturaE root),
  `<ds:Reference Id=".." Type=".." URI="..">`, `<ds:Object Encoding=".." Id=".." MimeType="..">`,
  `<xades:QualifyingProperties xmlns:xades=".." Id=".." Target=".." xmlns:ds="..">`. This rule is more
  precise than the short description in section 6. It also re-orders attributes of the user's own XML in
  enveloped/detached/enveloping output (e.g. `<doc z="1" b="2">` -> `<doc b="2" z="1">`; harmless for C14N).
* Empty elements are written self-closed `<x/>` (current JREs, also when the only child is an empty
  text node such as the jxades policy `Description`); some older samples show `<x></x>` for the latter.
  Irrelevant for signatures (C14N always writes `<x></x>`).
* Text/attribute escaping: standard (`&amp;`, `&lt;`, `&gt;`, `&quot;` in attributes, `\r` as `&#13;`);
  characters not representable in the output encoding become numeric character references.
* Optional stylesheet header: if the result is well-formed XML and `styleHref != null`, the first `>`
  of the output (end of the XML declaration) is replaced by
  `>\r\n<?xml-stylesheet type="<styleType or text/xsl>" href="<styleHref>"?>`. Only used by Enveloped
  XAdES/XMLdSig when a stylesheet was detected (practically never for XAdES, see 2.8).

### 2.3 Algorithm identifiers (`XMLConstants`)

Namespaces: `DSIGNNS = "http://www.w3.org/2000/09/xmldsig#"`. Object type
`OBJURI = "http://www.w3.org/2000/09/xmldsig#Object"`. Manifest type
`"http://www.w3.org/2000/09/xmldsig#Manifest"`. Base64 encoding/transform
`BASE64_ENCODING = "http://www.w3.org/2000/09/xmldsig#base64"`. Default MIME
`application/octet-stream`.

Signature algorithm (Java name, case-sensitive map key) -> `SignatureMethod` URI (`SIGN_ALGOS_URI`):

| Java names accepted | URI |
|---|---|
| `SHA1withRSA`, `RSA`, `SHA-1withRSA`, `SHA1withRSAEncryption`, `SHA-1withRSAEncryption`, `SHAwithRSAEncryption`, `SHAwithRSA` | `http://www.w3.org/2000/09/xmldsig#rsa-sha1` |
| `SHA256withRSA`, `SHA-256withRSA`, `SHA256withRSAEncryption`, `SHA-256withRSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` |
| `SHA384withRSA`, `SHA-384withRSA`, `SHA384withRSAEncryption`, `SHA-384withRSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha384` |
| `SHA512withRSA`, `SHA-512withRSA`, `SHA512withRSAEncryption`, `SHA-512withRSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512` |
| `SHA1withECDSA`, `ECDSA`, `SHA-1withECDSA`, `SHA1withECDSAEncryption`, `SHA-1withECDSAEncryption`, `SHAwithECDSAEncryption`, `SHAwithECDSA` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1` |
| `SHA224withECDSA`, `SHA-224withECDSA`, `SHA224withECDSAEncryption`, `SHA-224withECDSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224` |
| `SHA256withECDSA` (+ same 3 variants) | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` |
| `SHA384withECDSA` (+ variants) | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384` |
| `SHA512withECDSA` (+ variants) | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512` |

Anything else (e.g. `SHA1withDSA`, `NONEwithRSA`, RSASSA-PSS) -> error "Los formatos de firma XML no
soportan el algoritmo de firma ..." (`ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM` in XAdES sign;
`IllegalArgumentException` in cosign/countersign). XAdES additionally rejects any algorithm whose
upper-cased name starts with `MD` (`IllegalArgumentException`, "Decision 130/2011 CE").
Default algorithm when `null` is passed: `SHA512withRSA`.

ECDSA `SignatureValue` = raw `r || s` (each integer left-padded to the field size), as mandated by
XMLDSig 1.1 and produced by Santuario (Java 9+ uses `...withECDSAinP1363Format`). RSA = PKCS#1 v1.5.

Digest URIs (`MESSAGEDIGEST_ALGOS_URI`, keys lower-case): `sha1`/`sha-1` ->
`http://www.w3.org/2000/09/xmldsig#sha1`; `sha256`/`sha-256` -> `http://www.w3.org/2001/04/xmlenc#sha256`;
`sha384`/`sha-384` -> `http://www.w3.org/2001/04/xmldsig-more#sha384`; `sha512`/`sha-512` ->
`http://www.w3.org/2001/04/xmlenc#sha512`. XAdES uses digest **URIs** directly in extraParams
(`referencesDigestMethod`), default `http://www.w3.org/2001/04/xmlenc#sha512` (`XAdESConstants.DEFAULT_DIGEST_METHOD`).

`XAdESUtil.getDigestMethodByCommonName(name)` (used for policy hash algorithm, precalculated hash
algorithm, externally-detached digest): normalizes with `AOSignConstants.getDigestAlgorithmName` and
accepts only `SHA1` -> xmldsig#sha1, `SHA-256` -> xmlenc#sha256, `SHA-512` -> xmlenc#sha512; anything
else (including SHA-384) throws `NoSuchAlgorithmException`.

### 2.4 Canonicalization: what MUST be implemented

| Algorithm | URI | Where used |
|---|---|---|
| Inclusive C14N 1.0 (no comments) | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | Default `CanonicalizationMethod` of every SignedInfo (XAdES, XMLdSig, cosign, countersign); default data Transform; implicit node-set->octets conversion of every reference without transforms (SignedProperties, KeyInfo, Object, Manifest); countersignature reference transform; XAdES-T timestamp imprint; ODF/OOXML (see 7, 8) |
| Inclusive C14N 1.0 with comments | `...REC-xml-c14n-20010315#WithComments` | Only if the user passes it in `canonicalizationAlgorithm` |
| Exclusive C14N 1.0 (+ `#WithComments`) | `http://www.w3.org/2001/10/xml-exc-c14n#` | Only if passed in `canonicalizationAlgorithm` (no `InclusiveNamespaces` PrefixList is ever generated); also seen in third-party XML timestamps (validation only) |
| C14N 1.1 (+ `#WithComments`) | `http://www.w3.org/2006/12/xml-c14n11` | Only if passed in `canonicalizationAlgorithm` (Santuario accepts it) |
| OOXML RelationshipTransform | `http://schemas.openxmlformats.org/package/2006/RelationshipTransform` | OOXML only (section 8) |

Key requirements for the C14N engine:

* Must canonicalize **document subsets** (XMLDSig node-sets): an element subtree selected by `#id`
  (comments removed), the whole document minus `ds:Signature` subtrees (enveloped), and the result of
  XPath filters. In inclusive C14N the apex element of a subset must carry all in-scope namespace
  declarations inherited from its ancestors (e.g. `SignedProperties` gets `xmlns:ds` and `xmlns:xades`;
  in an enveloped document it also gets the document's default/other namespaces).
* Reference processing model (XMLDSig 4.3.3.2): a same-document URI (`""` or `#id`) yields a node-set
  without comments; a transform that needs octets triggers inclusive C14N; a final node-set is converted
  to octets with inclusive C14N 1.0. A transform that needs a node-set and receives octets parses them.
* The `CanonicalizationMethod` of `SignedInfo` is applied to the `ds:SignedInfo` element as it sits in
  the final tree (its in-scope namespaces = `xmlns:ds` from `ds:Signature` plus any ancestor
  declarations; e.g. a default namespace of an enveloped document root is inherited).

### 2.5 Transforms used / accepted

| Transform | URI | Parameters as serialized |
|---|---|---|
| Enveloped signature | `http://www.w3.org/2000/09/xmldsig#enveloped-signature` | none |
| XPath 1.0 filter | `http://www.w3.org/TR/1999/REC-xpath-19991116` | `<ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">EXPR</ds:XPath>` (the namespace map is always `{<signature prefix>: xmldsig ns}` and Santuario writes it as an explicit `xmlns:ds` attribute even if redundant) |
| XPath Filter 2.0 | `http://www.w3.org/2002/06/xmldsig-filter2` | `<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="subtract\|intersect\|union">EXPR</XPath>` (default namespace, no prefix - observed with Santuario 3.0.5 / JDK 21) |
| Base64 decode | `http://www.w3.org/2000/09/xmldsig#base64` | none. Input node-set -> string value of the text descendants -> Base64 decode |
| C14N variants | see 2.4 | none |

The only XPath expressions AutoFirma itself emits are `not(ancestor-or-self::ds:Signature)` (XAdES
enveloped, prefix = `ds` or the existing signature prefix on cosign) and the expressions of XMLdSig
(section 6). Generic XPath/XPath2 support is needed only for user-supplied `xmlTransforms` and for
validating third-party signatures. For the enveloped case the net effect equals "remove every
`ds:Signature` element (any depth, together with its subtree) and canonicalize the rest".

#### 2.5.1 User transforms: `xmlTransforms` syntax (`Utils.addCustomTransforms`, shared by XAdES and XMLdSig)

| Key | Meaning |
|---|---|
| `xmlTransforms` | Integer N (string). Default `0`. Must parse as int (otherwise `NumberFormatException` propagates). |
| `xmlTransform<i>Type` | i = 0..N-1 (zero-based). One of the four URIs: XPath, XPath2, Base64, Enveloped. Others -> warning, skipped. |
| `xmlTransform<i>Body` | XPath expression (required for XPath / XPath2; missing -> skipped). Single expression only. |
| `xmlTransform<i>Subtype` | XPath2 only: `subtract`, `intersect`, `union` (exact, lower case). Other -> skipped. |

XPath namespace map: `{prefix: "http://www.w3.org/2000/09/xmldsig#"}` where prefix is `ds` for XAdES
(and the XMLdSig prefix for XMLdSig). The user transforms are always placed **first** in the data
reference's `Transforms`, before any transform AutoFirma adds. They are added only to the main data
reference (not to style / SignedProperties / KeyInfo references) and are ignored by cosign (which copies
the original reference transforms) and countersign.

### 2.6 URI dereferencing (`dereference.CustomUriDereferencer`)

Used by XAdES signing (unless a custom dereferencer is installed, e.g. ASiC) and by validation.
Algorithm for a `Reference/@URI`:

1. Try the standard JSR-105 dereferencer (`""` = whole document without comments, `#id` = element
   whose attribute is *registered as an ID* - jxades registers every attribute named `Id` in the
   document before signing; `#xpointer(/)`, `#xpointer(id('x'))`; absolute `http(s)`/`file` URLs are
   fetched).
2. On failure:
   * `http://` / `https://`: GET the URL, parse it as XML (secure builder) and return it as node-set
     data (non-XML remote content therefore fails).
   * `""`: the whole owner document.
   * otherwise strip a leading `#` and look up `getElementById` (attribute name equalsIgnoreCase `Id`).
     Found -> that subtree as node-set (comments included, but they are removed by any later C14N
     without comments). Not found -> `URIReferenceException`.

ASiC uses `UriAndDataDereferencer` = the above, then, on failure, a map `{uri -> bytes}`: if the URI is
a key, return the bytes as octet stream.

### 2.7 Base64

* `es.gob.afirma.core.misc.Base64.encode` = standard alphabet, padding, **no line breaks**.
* Santuario is configured (`com.sun.org.apache.xml.internal.security.lineFeedOnly=true`,
  `org.apache.xml.security.ignoreLineBreaks=true`) so `DigestValue`, `SignatureValue`,
  `X509Certificate`, `Modulus`, etc. are written **without line breaks** (otherwise Java would emit
  `\r\n` -> `&#13;`). jxades `Base64.encodeBytes` (CertDigest, policy hash) also has no line breaks.
* `Base64.isBase64(bytes)`: every char in the set `A-Za-z0-9=_-\t\n+/\r~`, `=` only in the last two
  positions, and (count of chars excluding `\r`/`\n`) % 4 == 0.

### 2.8 Stylesheets (`style.XmlStyle`) - XML data only, ignored if `ignoreStyleSheets=true`

`new XmlStyle(data, headless, allowExternal)`:

1. Find the first `<?xml-stylesheet ` in the text (decoded with the platform charset); take up to the
   next `>`, strip `<?xml-stylesheet `, `?>`, quotes, convert spaces to newlines and parse as
   `key=value` properties. If both `type` and `href` exist, dereference `href`:
   * build a URI (`AOUtil.createURI`; scheme-less -> `file://`); `file:` -> rejected; if
     `!allowExternal`, `http`, `https`, `ftp`, `ftps` -> rejected; otherwise load it.
   * on rejection/failure: if the last path segment starts with `#` -> `IsInnerlException`; else if
     `!headless` and href starts with `file://` -> ask the user to pick the file (UI dialog); else
     `CannotDereferenceException`.
   * parse the loaded bytes as XML (`ReferenceIsNotXmlException` otherwise).
2. Result: `element` = root of the stylesheet document unless href is http(s) (then null), `type`,
   `href`, `encoding` (= stylesheet's XML declaration encoding).

**XAdES calls it with `allowExternal=false` and `headless` defaulting to `true`**, and on any exception
keeps an *empty* `XmlStyle` (no href, no element). Therefore, in practice (headless), XAdES never signs
or embeds a stylesheet and the `<?xml-stylesheet?>` PI of the input is **dropped** from Enveloped output
(only the document element is copied into the output document). The STYLE/StyleObject/StyleReference
code paths (2.8.1) only run when `headless=false` and the user picks a local file. XMLdSig has its own
handling (section 6).

#### 2.8.1 XAdES stylesheet paths (only reachable with an embedded style element)

* Detached: `<STYLE Id="STYLE-<uuid>" MimeType="<type>" Encoding="<style enc>">` + clone of the XSL root
  appended to the signature root after CONTENT; reference `Id="StyleReference-<uuid>" URI="#STYLE-<uuid>"`
  with the C14N transform, no Type.
* Enveloping: `ds:Object Id="StyleObject-<uuid>" MimeType=<type> Encoding=<enc>` holding the XSL root;
  reference `URI="#StyleObject-<uuid>" Type=OBJURI Id="StyleReference-<uuid>"` with C14N.
* Enveloped: `ds:Object Id="STYLE-<uuid>" MimeType=<type or text/xsl> Encoding=<enc>` added after the
  QualifyingProperties object; reference `URI="#STYLE-<uuid>" Type=OBJURI Id="StyleReference-<uuid>"`
  with C14N (or no transforms if canonicalization is `none`); the `<?xml-stylesheet?>` header is
  re-inserted on output.
* Remote (http/https) stylesheet references (`Reference URI=<href>`, C14N) exist in the code for all
  formats but are unreachable with `allowExternal=false`.

---

## 3. XAdES signer (`AOXAdESSigner`)

Java: `afirma-crypto-xades/src/main/java/es/gob/afirma/signers/xades/`. Format name
`AOSignConstants.SIGN_FORMAT_XADES = "XAdES"`. Supports XAdES-BES/EPES (ETSI TS 101 903 v1.3.2 style,
`SigningCertificate`) and "baseline" B-Level (ETSI EN 319 132-1, `SigningCertificateV2`), with optional
XAdES-T (`SignatureTimeStamp`) on simple signatures. All behaviour in this section was confirmed by
compiling the real sources (afirma-core, core-xml, core-pkcs7(-tsp), xades + jxades 0.2.2 + Santuario
3.0.5, JDK 21) and running them; outputs were verified with a JSR-105 validator (section 13 shows them).

Class map:

| Class | Responsibility |
|---|---|
| `AOXAdESSigner` | Public `AOSigner`; clones extraParams and removes `validatePkcs1`; sign -> `XAdESSigner.sign` then `XAdESTspUtil.timestampXAdES`; cosign -> `XAdESCoSigner`; countersign -> `XAdESCounterSigner`; structure/isSign/getData/getSignInfo. Holds an optional `URIDereferencer` (`setUriDereferencer`, used by ASiC). |
| `XAdESSigner` | The sign algorithm (static) |
| `XAdESCoSigner`, `XAdESCounterSigner` | Multi-signature |
| `XAdESUtil` | Detection helpers, jxades factory (`newInstance`), manifest, CTI parsing, root element creation |
| `XAdESCommonMetadataUtil` | Policy, production place, signer role |
| `AOXMLAdvancedSignature` | Subclass of jxades `XMLAdvancedSignature`: builds KeyInfo, SignedInfo, signs with Santuario, verifies PKCS#1 |
| `EscapeHelper` | DN escaping for `KeyName` / `X509IssuerSerial` in KeyInfo |
| `XAdESTspUtil` | XAdES-T `SignatureTimeStamp` |
| `DataObjectFormatParser` | Reads existing `DataObjectFormat` (cosign of manifest signatures) |
| `XAdESConstants`, `XAdESExtraParams` | Constants |

### 3.1 Public API

| Method | Behaviour |
|---|---|
| `sign(data, algorithm, key, certChain, extraParams) -> byte[]` | 3.3-3.9, then XAdES-T if `tsaURL` (3.10) |
| `cosign(data, sign, algorithm, key, certChain, extraParams)` | `data` ignored. Parse `sign` (failure -> `AOInvalidSignatureFormatException`), `isSign` else `AOInvalidSignatureFormatException("No se ha indicado una firma XAdES para cofirmar")`, `checkCompatibility`, `checkSignProfile`, then 3.11 |
| `cosign(sign, algorithm, key, certChain, extraParams)` | same with `data = null` |
| `countersign(sign, algorithm, CounterSignTarget, Object[] targets, key, certChain, extraParams)` | parse, `checkCompatibility`, `checkSignProfile`, `isSign` (else "No se ha indicado una firma XAdES para contrafirmar"), then 3.12 |
| `getSignersStructure(sign, asSimpleSignInfo)` / `(sign, params, asSimpleSignInfo)` | 3.13; returns `null` if `sign` does not parse; throws `AOInvalidSignatureFormatException` if not `isSign`. `params` ignored |
| `isSign(sign)` / `(sign, params)` | 3.14.1; `false` on `null` or unparseable |
| `isValidDataFile(data)` | `data != null` |
| `getSignedName(name, inText)` | `name + (inText ?: "") + ".xsig"` |
| `getData(sign)` / `(sign, params)` | 3.14.3 |
| `getSignInfo(data)` / `(data, params)` | `AOSignInfo("XAdES")` with variant (3.14.2); `IllegalArgumentException` on null; `AOInvalidSignatureFormatException` if not XML or not `isSign` |
| `needData(cryptoOperation, config)` | `true` unless op equalsIgnoreCase `"SIGN"` and config non-null and (format == `XAdES Externally Detached` or `useManifest=true`) |
| static helpers | `isDetached(Element)`, `isExternallyDetached`, `isManifestSignature`, `isEnveloped`, `isEnveloping` (all on the **first** signature), `checkCompatibility(Document)` |

### 3.2 extraParams (complete list)

All values are strings (`Properties`); booleans use `Boolean.parseBoolean` (only case-insensitive `"true"`
is true). Keys are case-sensitive. "S/C/CS" = read by sign / cosign / countersign.

#### 3.2.1 Format and data

| Key | Values | Default | Ops | Effect |
|---|---|---|---|---|
| `format` | `XAdES Enveloping`, `XAdES Enveloped`, `XAdES Detached`, `XAdES Externally Detached` | `XAdES Enveloping` | S | Signature variant. Validated with `equalsIgnoreCase` (`Utils.checkIllegalParams`; anything else -> `UnsupportedOperationException("El formato de firma '..' no esta soportado")`), but all later branches use case-sensitive `equals` (quirk: e.g. `xades enveloping` passes validation and produces a signature whose only data-related output is a `DataObjectFormat`, with no data reference). |
| `mode` | anything | - | S | Deprecated; only logs a warning in XAdES. |
| `uri` | URI string | - | S | Externally Detached: `Reference/@URI` of the data (mandatory unless `useManifest`; missing -> `UnsupportedOperationException("Las firmas XML Externally Detached necesitan la URI ...")`). Ignored (warning) for other formats. Also the single-reference form of manifest signatures. Parsed with `AOUtil.createURI` only to check presence/validity (an unparseable value is treated as absent); the raw string is what is written. |
| `useManifest` | boolean | `false` | S | Forces `format = XAdES Externally Detached` and puts the data references in a `ds:Manifest` (3.9.2). |
| `uri<i>`, `md<i>`, `mimeType<i>`, `contentTypeOid<i>`, `encoding<i>` | i = 1, 2, 3 ... (1-based, contiguous; stops at the first missing `uri<i>`) | - | S (manifest without `uri`) | One manifest reference per i: URI, Base64 digest (mandatory: missing -> `AOException` 610201; bad Base64 -> 610202), DataObjectFormat MIME / OID / encoding. No `uri1` -> `AOException` 610203. |
| `precalculatedHashAlgorithm` | `SHA1`, `SHA-256`, `SHA-512` (any spelling accepted by `getDigestAlgorithmName`, also the digest URIs) | **= `referencesDigestMethod`** | S | Digest algorithm of the external reference(s). Because its default is never null, **in Externally Detached (non-manifest) the `data` bytes are ALWAYS used verbatim as the DigestValue** (quirk, confirmed: data `hello world` -> `<ds:DigestValue>aGVsbG8gd29ybGQ=</ds:DigestValue>`). SHA-384 -> `AOException` 610004. |
| `nodeToSign` | value of an `Id` attribute (any case of the attribute name) | - | S | XML data only (non-XML -> `InvalidXMLException`). Signs only that element (3.4). |
| `insertEnvelopedSignatureOnNodeByXPath` | XPath 1.0 expression (namespace-unaware, no prefixes bound; evaluated with the root element as context) | - | S (Enveloped) | Parent under which the Signature is appended (first match; 0 matches or invalid -> `AOException` 610007; >1 -> warning, first used). |
| `avoidEnvelopedTransformWhenSigningNode` | boolean | `false` | S (Enveloped, only if `nodeToSign` set) | Omit the `enveloped-signature` transform. |
| `avoidXpathExtraTransformsOnEnveloped` | boolean | `false` | S (Enveloped) | Omit the `not(ancestor-or-self::ds:Signature)` XPath transform. |
| `facturaeSign` | boolean | `false` | S (Enveloped) | Omit both the C14N transform and the XPath transform of the enveloped reference (only `enveloped-signature` remains). Set internally by FacturaE. |
| `mimeType` | MIME string | auto (3.4.2) | S | `ds:Object/@MimeType`, `CONTENT/@MimeType`, `DataObjectFormat/MimeType`. |
| `contentTypeOid` | OID, with or without `urn:oid:` | derived from MIME | S | `DataObjectFormat/ObjectIdentifier/Identifier` (`urn:oid:` prefix added). |
| `encoding` | URI; the literal `base64` (any case) is mapped to `http://www.w3.org/2000/09/xmldsig#base64` | - | S, C | Must parse as `java.net.URI` (else `AOException` 610001). `ds:Object/@Encoding`, `CONTENT/@Encoding`, `DataObjectFormat/Encoding`. For binary data in Enveloping/Detached it is forced to the base64 URI. Declaring `base64` for data that IS valid Base64 makes AutoFirma embed it as-is (3.4.2). Not the output charset (see `outputXmlEncoding`). |
| `outputXmlEncoding` | charset name | input XML declaration encoding, else UTF-8 | S, C, CS | Output charset and XML declaration encoding. |
| `ignoreStyleSheets` | boolean | `false` | S | Skip `<?xml-stylesheet?>` processing (2.8). |
| `headless` | boolean | **`true`** | S | `false` allows a UI dialog for `file://` stylesheets. (The Javadoc spells it `headLess`; the code key is `headless`.) |
| `avoidBase64Transforms` | boolean | `false` | S | Do not declare the `#base64` transform for data that AutoFirma Base64-encoded (the reference then digests the C14N of the `ds:Object`/`CONTENT` element). |
| `xmlTransforms`, `xmlTransform<i>Type`, `xmlTransform<i>Subtype`, `xmlTransform<i>Body` | see 2.5.1 | `0` | S | Custom transforms, prepended to the data reference transforms. |
| `RootXmlNodeName` | qualified name | `AFIRMA` | S (Detached, Externally Detached, Enveloping before unwrap) | Name of the wrapper root element. |
| `RootXmlNodeNamespace` | namespace URI | none | S | If set, root created with `createElementNS(ns, name)`. |
| `RootXmlNodeNamespacePrefix` | prefix or `xmlns:prefix` | none | S | If set (with namespace), adds attribute `xmlns:<prefix>="<ns>"` to the root. |

#### 3.2.2 Cryptographic / structural

| Key | Values | Default | Ops | Effect |
|---|---|---|---|---|
| `referencesDigestMethod` | digest URI accepted by Santuario (`...xmldsig#sha1`, `...xmlenc#sha256`, `...xmldsig-more#sha384`, `...xmlenc#sha512`, ...) | `http://www.w3.org/2001/04/xmlenc#sha512` | S, C, CS | DigestMethod of every Reference (data, SignedProperties, KeyInfo, manifest), and of `CertDigest` (3.5.3). Invalid -> `AOException` 610002. |
| `canonicalizationAlgorithm` | C14N URI or `none` (case-insensitive, sign only) | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | S, C, CS | SignedInfo `CanonicalizationMethod` and the C14N transform added to XML data references / manifest reference / countersignature reference. `none`: no C14N transforms on data references; SignedInfo uses inclusive C14N. In cosign/countersign `none` is not special (countersign then fails). Invalid -> 610003. |
| `xadesNamespace` | `http://uri.etsi.org/01903#`, `.../v1.1.1#`, `.../v1.2.2#`, `.../v1.3.2#`, `.../v1.4.1#` (anything is accepted at sign time) | `http://uri.etsi.org/01903/v1.3.2#` | S | Namespace of ALL `xades:` elements (QualifyingProperties and below, even with 1.4.1 - non-standard but what is produced). Ignored (removed with `signedPropertiesTypeUrl`) when `profile=baseline` and the namespace is not 1.3.2/1.4.1. Ignored in cosign (taken from the existing signature). |
| `signedPropertiesTypeUrl` | URI | `http://uri.etsi.org/01903#SignedProperties` (for every namespace) | S | `Type` of the SignedProperties Reference. Ignored in cosign/countersign (copied from the existing signature). |
| `profile` | `advanced` \| `baseline` (case-insensitive at sign) | `advanced` | S (C/CS: overwritten, see 3.11) | `baseline` -> jxades `B_LEVEL` (SigningCertificateV2, SignatureProductionPlaceV2, SignerRoleV2) and forces `keepKeyInfoUnsigned=true`. Anything else (e.g. `B-B-Level`) = advanced (EPES). |
| `includeOnlySignningCertificate` (sic) | boolean | `false` | S, C, CS | Only `certChain[0]` in `X509Data`. In cosign/countersign it also switches to jxades' own KeyInfo builder (3.11.5). |
| `addKeyInfoKeyValue` | boolean | `true` | S, C, CS | Add `ds:KeyValue` (never for EC keys). |
| `addKeyInfoKeyName` | boolean | `false` | S, C, CS | Add `ds:KeyName` (3.6). |
| `addKeyInfoX509IssuerSerial` | boolean | `false` | S, C, CS | Add `ds:X509IssuerSerial` as a direct child of `ds:KeyInfo` (3.6). |
| `keepKeyInfoUnsigned` | boolean | `false` (`true` forced when `profile=baseline` in sign) | S, C, CS | Do not add the Reference to `#<sigId>-KeyInfo`. Note: in cosign/countersign the baseline profile does NOT force it. |
| `validatePkcs1` | boolean | `true` | internal | Verify the produced SignatureValue with the certificate public key (3.4.9). Removed from user params by `AOXAdESSigner`; tri-phase server sets it to `false` internally. |

#### 3.2.3 Signed properties metadata

| Key | Values | Default | Ops | Effect |
|---|---|---|---|---|
| `policyIdentifier` | URL, `urn:oid:...` or bare OID | - | S, C, CS | `SignaturePolicyIdentifier` (3.5.4). A bare OID (validated with `org.ietf.jgss.Oid`) gets the `urn:oid:` prefix. |
| `policyIdentifierHash` | Base64 digest | - | S, C, CS | `SigPolicyHash/DigestValue`. If absent (or `policyIdentifierHashAlgorithm` absent), jxades downloads `policyIdentifier` as a URL and uses SHA-1 of the content; if that fails (e.g. URN) the policy is silently omitted (warning). |
| `policyIdentifierHashAlgorithm` | `SHA1`, `SHA-256`, `SHA-512` or their URIs | - | S, C, CS | `SigPolicyHash/DigestMethod/@Algorithm` (via `getDigestMethodByCommonName`; unsupported -> `AOException` UNSUPPORTED_POLICY_HASH_ALGORITHM). |
| `policyDescription` | text | `""` | S, C, CS | `SigPolicyId/Description` (always present, empty if not given). |
| `policyQualifier` | URL | - | S, C, CS | `SigPolicyQualifiers/SigPolicyQualifier/SPURI`. |
| `signerClaimedRoles` | `role1\|role2\|...` | - | S, C, CS | `SignerRole/ClaimedRoles/ClaimedRole*` (EPES) or `SignerRoleV2/ClaimedRoles/ClaimedRole*` (baseline). Blank items dropped; if none remain no element. |
| `signatureProductionCity` | text | - | S, C, CS | `City` |
| `signatureProductionStreetAddress` | text | - | S, C, CS | `StreetAddress` - **baseline only** (V2) |
| `signatureProductionProvince` | text | - | S, C, CS | `StateOrProvince` |
| `signatureProductionPostalCode` | text | - | S, C, CS | `PostalCode` |
| `signatureProductionCountry` | text | - | S, C, CS | `CountryName` |
| `commitmentTypeIndications` | integer N >= 1 | - | S only | Enables CTIs. **Indices 0..N inclusive are read** (quirk: N+1 slots; missing slots skipped). Non-integer or < 1 -> ignored (log). |
| `commitmentTypeIndication<n>Identifier` | `1`..`6` | - | S | 1 ProofOfOrigin, 2 ProofOfReceipt, 3 ProofOfDelivery, 4 ProofOfSender, 5 ProofOfApproval, 6 ProofOfCreation -> `http://uri.etsi.org/01903/v1.2.2#ProofOf...`. Missing -> slot skipped; other value -> skipped (log). |
| `commitmentTypeIndication<n>Description` | text | - | S | `CommitmentTypeId/Description` (element always present, empty if absent). |
| `commitmentTypeIndication<n>DocumentationReferences` | `url1\|url2` | - | S | `DocumentationReferences/DocumentationReference*`; each must parse as `java.net.URL` (invalid ones skipped); written as `URL.toString()`. |
| `commitmentTypeIndication<n>CommitmentTypeQualifiers` | `q1\|q2` | - | S | `CommitmentTypeQualifiers/CommitmentTypeQualifier*` (element always present, possibly empty). |

#### 3.2.4 Multi-signature control and others

| Key | Values | Default | Ops | Effect |
|---|---|---|---|---|
| `allowSignLTSignature` | boolean | unset | C, CS | If the document contains an `ArchiveTimeStamp` (1.4.1, 1.3.2 or 1.2.2 namespace, direct child of a signature's UnsignedSignatureProperties): unset -> `SigningLTSException` (asks the user); `false` -> `SigningLTSException` marked denied (quirk: cosign marks the *cause* exception as denied, not the thrown one; countersign marks the thrown one); `true` -> proceed. The UnsignedProperties lookup used here only matches the 1.3.2 namespace. |
| `allowXadesEnvelopedWithoutXPath` | boolean | unset | C (Enveloped) | Original enveloped reference has no XPath transform containing `Signature`: unset -> `NotFoundXPathException` (ask user); `false` -> `AOException` 501011; `true` -> add `not(ancestor-or-self::<prefix>:Signature)` to the copied transforms. |
| `avoidAGEPolicyIncompatibilities` | boolean | unset | C (Enveloping) | Cosigning an enveloping signature with the AGE policy (`urn:oid:2.16.724.1.3.1.1.2.1.9` - any identifier listed in `policy.properties`): unset -> `SignaturePolicyIncompatibilityException`; `true` -> remove all `policy*` params and continue; `false` -> `AOException` SIGNING_WITH_POLICY_INCOMPATIBILITY. |
| `confirmDifferentProfile` | **`java.lang.Boolean` object** (a String `"true"` does not work) | - | C, CS | If `Boolean.TRUE` and the requested profile differs from the existing signature's, ask the user (UI). Otherwise the profile is silently set to the existing one. |
| `SignatureId` | string | - | batch | Only propagated by FacturaE (allowed list) for batch processing; not used to build ids. |
| `tsaURL`, `tsaPolicy`, `tsaHashAlgorithm`, `tsaRequireCert`, `tsaUsr`, `tsaPwd`, `tsaSslKeyStore`, `tsaSslKeyStorePassword`, `tsaSslKeyStoreType`, `tsaSslTrustStore`, `tsaSslTrustStorePassword`, `tsaSslTrustStoreType`, `tsaExtensionOid`, `tsaExtensionValueBase64`, `tsaExtensionCritical`, `verifyHostname` | see 3.10 | - | S | XAdES-T. `tsType` is NOT consulted by XAdES. |

Keys that do **not** exist for XAdES (requested in some checklists; a port must ignore them):
`signerCertifiedRoles` (no certified roles anywhere in XML signers), `applySystemDate` (CMS only),
`xmlSignatureNamespacePrefix` / `xadesNamespacePrefix` (prefixes are fixed to `ds` / `xades`; XMLdSig
has `xmlSignaturePrefix`), `signatureReason`, `signatureAddress1/2` etc. (OOXML/PAdES).

### 3.3 sign(): parameter phase

1. `algorithm = algorithm ?: "SHA512withRSA"`; reject `MD*` (`IllegalArgumentException`).
2. `checkParams`: if `profile=baseline`: warn on SHA-1 signature/reference algorithms; if
   `xadesNamespace` is set and not 1.3.2/1.4.1, remove `xadesNamespace` and `signedPropertiesTypeUrl`.
3. `algoUri = SIGN_ALGOS_URI[algorithm]`, else `AOException(UNSUPPORTED_SIGNATURE_ALGORITHM)`.
4. Read all params (3.2). `encoding` `base64` -> base64 URI; must be a valid `URI`.
5. `keepKeyInfoUnsigned = profile.equalsIgnoreCase("baseline") || keepKeyInfoUnsigned param`.
6. `useManifest` -> `format = "XAdES Externally Detached"`.
7. `Utils.checkIllegalParams(format, mode, useManifest, uri, ..., xades=true)` (see 3.2.1).
8. Empty/null `data` -> `AOException(DATA_NOT_FOUND)` unless format is Externally Detached.

### 3.4 sign(): data element and container (per format)

Fresh UUIDs (`UUID.randomUUID()`, lower-case, hyphenated) are generated per call:
`contentId = "CONTENT-<u1>"`, `styleId = "STYLE-<u2>"`, `referenceId = "Reference-<u3>"`,
`referenceStyleId = "StyleReference-<u4>"`, enveloping `objectId = "Object-<u5>"`, root
`<RootXmlNodeName>-Root-<u6>`, signature prefix `sigId = "Signature-<u7>"`.

#### 3.4.1 Is the data XML?

`docum = (data != null && AOFileUtils.isXML(data)) ? parse(data) : null` (secure SAX check, so DOCTYPE
-> not XML; then parse with `Utils.getNewDocumentBuilder`).

#### 3.4.2 XML data (`docum != null`)

* Stylesheet: `new XmlStyle(data, headless, false)` unless `ignoreStyleSheets` (2.8).
* `mimeType = "text/xml"` if absent or `application/octet-stream`.
* Output properties from the input (encoding = `outputXmlEncoding` or input declaration encoding).
* **Detached**:
  * with `nodeToSign` (element found via case-insensitive `Id` lookup over the whole document):
    * not the root: the original document is the signature document, nothing is wrapped, and the
      Signature will be appended to the **parent of the signed node** (as its last child).
    * the root: the original root element (with its `Id`) is moved directly under the new wrapper root
      (no CONTENT).
  * without `nodeToSign`: `<CONTENT Id="CONTENT-<u1>" MimeType="<mimeType>" [Encoding="<encoding>"]>` +
    the original document element moved inside it (Encoding only if the param was given).
* **Enveloping / Enveloped / Externally Detached**: data element = the original document element.
  Everything outside the root (prolog comments, PIs incl. `<?xml-stylesheet?>`, DOCTYPE) is lost.

#### 3.4.3 Non-XML data

* Enveloped or `nodeToSign` set -> `InvalidXMLException` ("Las firmas XAdES Enveloped solo pueden
  realizarse sobre datos XML", code 510002).
* Detached / Enveloping: data element `<CONTENT Id="CONTENT-<u1>">` in a scratch document:
  * if `Base64.isBase64(data)` **and** `encoding` == base64 URI ("pre-encoded"): text =
    `Base64.encode(Base64.decode(data))` (normalized), `mimeType` = param, else `MimeHelper` on the
    decoded bytes, else `application/octet-stream`; **no Base64 transform** will be declared;
  * otherwise: text = `Base64.encode(data)`, `mimeType` = param, else `MimeHelper(data)`, else
    `application/octet-stream`; `wasEncodedToBase64 = true` (Base64 transform declared unless
    `avoidBase64Transforms`);
  * `encoding` := `http://www.w3.org/2000/09/xmldsig#base64`; attributes `MimeType`, `Encoding` set.
* Externally Detached: no data element.

#### 3.4.4 Container document

* Enveloped: new document whose root is the adopted data element (the user's root).
* Detached with `nodeToSign` != root: the user's document itself.
* Otherwise: new document with root = `XAdESUtil.getRootElement`: `createElement(RootXmlNodeName)` (or
  `createElementNS(ns, name)` + optional `xmlns:<prefix>` attribute), attribute
  `Id="<RootXmlNodeName>-Root-<u6>"` - default `<AFIRMA Id="AFIRMA-Root-<uuid>">` (quirk: with a
  prefixed name the Id contains a colon, e.g. ASiC `Id="asic:XAdESSignatures-Root-<uuid>"`).
  Detached: the CONTENT (or the moved root) is appended to it.

#### 3.4.5 Transforms and the data Reference

`T` = [custom `xmlTransforms` (2.5.1)] then, per format. `C14N` below = `canonicalizationAlgorithm`
transform (absent when `none`).

| Format | Data reference | Transforms (in order) | Type |
|---|---|---|---|
| Enveloping, XML | `URI="#Object-<u5>"` (or `#<nodeToSign>` if given; the node is inside the copied document in the Object) `Id="Reference-<u3>"` | `T`, `C14N` | `http://www.w3.org/2000/09/xmldsig#Object` (null when `nodeToSign`) |
| Enveloping, binary | same | `T`, `#base64` (if AutoFirma encoded and not avoided) | `...#Object` |
| Detached, XML | `URI="#CONTENT-<u1>"` (or `#<nodeToSign>`) | `T`, `C14N` | none |
| Detached, binary | `URI="#CONTENT-<u1>"` | `T`, `#base64` (if applicable) | none |
| Enveloped | `URI=""`, or `URI="#<id>"` if `nodeToSign` is set or the root element has a non-empty `Id` attribute (exact name `Id`) | `T`, `enveloped-signature` (unless `avoidEnvelopedTransformWhenSigningNode`), `C14N` (unless `facturaeSign`), XPath `not(ancestor-or-self::ds:Signature)` with `{ds: xmldsig}` (unless `facturaeSign` or `avoidXpathExtraTransformsOnEnveloped`) | none |
| Externally Detached | `URI="<uri>"` (verbatim), `Id="Reference-<u3>"`, DigestMethod = `getDigestMethodByCommonName(precalculatedHashAlgorithm)`, DigestValue = `data` (3.9.1) | none | none |
| Manifest | see 3.9.2 | | |

Stylesheet references, if any, follow the data reference (2.8.1).

Signature insertion parent: Enveloped -> XPath result if `insertEnvelopedSignatureOnNodeByXPath`, else the
`nodeToSign` element (so the Signature becomes the last child of the signed element; the enveloped
transform removes it), else the root. Detached with non-root `nodeToSign` -> parent of that node. All
other cases -> the container root. The Signature is always appended as **last child** of that parent.

#### 3.4.6 jxades instance and properties

`XAdESUtil.newInstance(profile, xadesNamespace, "xades", "ds", referencesDigestMethod, doc, parent, cert0)`:
`profile=baseline` -> `XAdES.B_LEVEL` (`BLevelXAdESImpl`), else `XAdES.EPES`
(`ExplicitPolicyXAdESImpl`). Before creating it, jxades calls `setIdAttribute("Id")` on every element of
the document having a non-empty `Id` attribute (so `#id` references resolve). Then:

* EPES: `setSigningCertificate(cert0)`; B-Level: `setSigningCertificateV2(cert0, null)` (no IssuerSerialV2
  value - see 3.5.3).
* `XAdESCommonMetadataUtil.addCommonMetadata`: policy (both), `SignatureProductionPlace` + `SignerRole`
  (EPES only), `SignatureProductionPlaceV2` + `SignerRoleV2` (B-Level only).
* `DataObjectFormat`s: one per data reference (`ObjectReference="#Reference-<u3>"`), or one per
  manifest reference (3.9.2). Built by `createDataObjectFormat(refId, mimeType, oid, encoding)`:
  * OID = `contentTypeOid`, else `MimeHelper.transformMimeTypeToOid(mimeType)`, but dropped if
    `mimeType != application/octet-stream` and the result is the default `1.2.840.113549.1.7.1`;
    no OID if `mimeType` is null.
  * `urn:oid:` prefix added if missing; `ObjectIdentifier/Identifier/@Qualifier="OIDAsURN"`.
  * `MimeType` = mimeType or `application/octet-stream`; `Encoding` = encoding (empty element if null);
    `Description` always present and empty.
* `CommitmentTypeIndication`s (sign only): `ObjectReference` = `#Reference-<u3>`.
* `AOXMLAdvancedSignature`: SignedProperties Type URL, digest method, SignedInfo canonicalization
  (`canonicalizationAlgorithm`, or inclusive if `none`), URI dereferencer (custom or
  `CustomUriDereferencer`).
* Enveloping: the data `ds:Object` (`Id="Object-<u5>" MimeType="<mimeType or application/octet-stream>"
  [Encoding="<encoding>"]`, content = the XML element, or the Base64 text node) is added **before**
  signing, so it precedes the QualifyingProperties object. Manifest: `ds:Object Id="ManifestObject-..."`
  likewise.

#### 3.4.7 Signature assembly (`AOXMLAdvancedSignature.sign`)

1. Build `QualifyingProperties` (3.5) inside a new `ds:Object` (no Id/MimeType/Encoding) and append the
   SignedProperties reference to the reference list.
2. (Enveloped + embedded stylesheet only) add the `STYLE-<u2>` Object.
3. Reference list (= SignedInfo order): data reference(s), style reference(s), SignedProperties
   reference `<ds:Reference Type="<signedPropertiesTypeUrl>" URI="#<sigId>-SignedProperties">` (no Id,
   no Transforms, DigestMethod = referencesDigestMethod), then - unless `keepKeyInfoUnsigned` -
   `<ds:Reference URI="#<sigId>-KeyInfo">` (no Id, no Type, no Transforms).
4. `SignedInfo` = `CanonicalizationMethod`, `SignatureMethod(algoUri)`, references. No Id.
5. `KeyInfo` (3.6) with `Id="<sigId>-KeyInfo"`.
6. `ds:Signature Id="<sigId>-Signature"`, `ds:SignatureValue Id="<sigId>-SignatureValue"`. Child order:
   `SignedInfo, SignatureValue, KeyInfo, Object*` (Objects in insertion order: data/manifest/style
   objects added before signing, then the QualifyingProperties object, then the enveloped style object).
7. Namespace prefixes: `ds` for xmldsig (declared on `ds:Signature`), `xades` for the XAdES namespace
   (declared on `QualifyingProperties`, which also re-declares `xmlns:ds`).
8. Sign: compute every reference digest, canonicalize SignedInfo, sign with the private key (Java
   algorithm from the URI; EC -> P1363 `r||s`). BouncyCastle EC keys are converted to JCE keys;
   Windows CAPI keys force the `SunMSCAPI` provider (irrelevant for Rust). jMulticard
   (DNIe) errors are mapped to `LockedKeyStoreException` (card locked), `PinException` (bad PIN),
   `AuthenticationException`, `AOCancelledSMOperationException`.
9. If `validatePkcs1` (default): verify the SignatureValue over the canonicalized SignedInfo with
   `certChain[0]`'s public key (`AOSignConstants.composeSignatureAlgorithmName(uri, keyAlg)`, ECDSA in
   P1363 format); failure -> `XMLSignatureException("El PKCS#1 de la firma no se ha generado con la clave
   publica indicada")` -> `AOException` 213001 (ETSI TS 119 102-1 recommendation).

#### 3.4.8 Output

* Enveloping: if the container holds exactly one `ds:Signature` (namespace-aware count), that Signature
  becomes the root of a new document (the `AFIRMA` wrapper disappears). If the signed XML itself already
  contained signatures, the wrapper stays.
* Serialization with `Utils.writeXML` (2.2): Enveloped passes the stylesheet href/type (null in practice).
* Then `XAdESTspUtil.timestampXAdES` (3.10), which re-parses and re-serializes only when `tsaURL` is set.

### 3.5 QualifyingProperties (exact content)

```text
<ds:Object>
 <xades:QualifyingProperties xmlns:xades=NS xmlns:ds=DSIG Id="<sigId>-QualifyingProperties" Target="#<sigId>-Signature">
  <xades:SignedProperties Id="<sigId>-SignedProperties">
   <xades:SignedSignatureProperties>
     ... (order below)
   </xades:SignedSignatureProperties>
   <xades:SignedDataObjectProperties>          (only if >=1 DataObjectFormat or CTI)
     <xades:DataObjectFormat ObjectReference="#Reference-...">*   (one per data reference)
     <xades:CommitmentTypeIndication>*
   </xades:SignedDataObjectProperties>
  </xades:SignedProperties>
 </xades:QualifyingProperties>
</ds:Object>
```

No `UnsignedProperties` at creation (added later by countersign / XAdES-T).

#### 3.5.1 Element order inside `SignedSignatureProperties` (jxades enum order - MUST replicate)

jxades iterates its `XAdES.Element` enum in declaration order. Resulting order:

* EPES/advanced: `SigningTime`, `SigningCertificate`, `SignaturePolicyIdentifier`?,
  `SignatureProductionPlace`?, `SignerRole`?
* B-Level/baseline: `SigningTime`, `SignaturePolicyIdentifier`?, **`SigningCertificateV2`**,
  `SignatureProductionPlaceV2`?, `SignerRoleV2`?

Quirk (confirmed on real output): with a policy, a baseline signature places
`SignaturePolicyIdentifier` **before** `SigningCertificateV2` (EN 319 132-1 XSD order would be
SigningTime, SigningCertificateV2, SignaturePolicyIdentifier, ...). Side effect:
`XAdESUtil.checkCompatibility` detects "baseline" by looking at the **2nd child** of the first
`SignedSignatureProperties` being `SigningCertificateV2`, so baseline signatures *with* a policy are not
recognized as baseline when cosigning/countersigning (the new signature then uses the advanced profile).

#### 3.5.2 `SigningTime`

Always present, always "now" (jxades ignores any configured date): `SimpleDateFormat
"yyyy-MM-dd'T'HH:mm:ssZ"` in the JVM default time zone, with a `:` inserted before the last two
characters -> `2026-10-16T13:39:15+02:00`. No fractional seconds. (UTC renders as `+00:00`.)

#### 3.5.3 `SigningCertificate` (EPES) and `SigningCertificateV2` (B-Level)

```xml
<xades:SigningCertificate>
  <xades:Cert>
    <xades:CertDigest>
      <ds:DigestMethod Algorithm="<referencesDigestMethod URI>"/>
      <ds:DigestValue>BASE64(H(cert0.DER))</ds:DigestValue>
    </xades:CertDigest>
    <xades:IssuerSerial>
      <ds:X509IssuerName>ISSUER_DN_JAVA</ds:X509IssuerName>
      <ds:X509SerialNumber>DECIMAL_SERIAL</ds:X509SerialNumber>
    </xades:IssuerSerial>
  </xades:Cert>
</xades:SigningCertificate>

<xades:SigningCertificateV2>
  <xades:Cert>
    <xades:CertDigest> (same) </xades:CertDigest>
    <xades:IssuerSerialV2/>            <!-- always present and EMPTY -->
  </xades:Cert>
</xades:SigningCertificateV2>
```

* Only the signing certificate (no chain). No `URI` attribute on Cert.
* Hash actually computed (quirk - may not match the declared URI):
  * V1: SHA-256 if the URI is `xmlenc#sha256`, SHA-512 if `xmlenc#sha512`, **SHA-1 otherwise** (so the
    `xmldsig-more#sha384` URI is declared with a SHA-1 value).
  * V2: SHA-512 if `xmlenc#sha512`, **SHA-256 otherwise** (so the SHA-1 URI is declared with a SHA-256
    value).
* `ds:DigestMethod/@Algorithm` is created with `setAttributeNS("ds", "Algorithm", ...)` (namespace URI
  literally `"ds"`, no prefix): it serializes and canonicalizes as a plain `Algorithm` attribute.
* `X509IssuerName` = Java `X509Certificate.getIssuerDN().getName()`, i.e. `sun.security.x509.X500Name
  .toString()`: RDNs from most specific to least (reverse of DER order), separator `", "` (comma +
  space), multi-valued RDN AVAs joined with `" + "`, keywords `CN C L ST O OU T IP STREET DC DNQUALIFIER
  SURNAME GIVENNAME INITIALS GENERATION EMAILADDRESS UID SERIALNUMBER`, other attribute types as
  `OID.<dotted>` (e.g. `OID.2.5.4.97=VATES-A40573396`), string values quoted with `"` when they contain
  `, = \n + < > # ; \ "` or leading/trailing spaces, non-string values as `#<hex DER>`. Examples:
  `CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES`,
  `CN=ACCV ECC1 CLIENTE, OID.2.5.4.97=VATES-A40573396, O=ISTEC, L=BURJASSOT, ST=VALENCIA, C=ES`.
  (Validators compare DNs semantically; byte parity only matters for SignedProperties reproducibility.)
* `X509SerialNumber` = decimal `BigInteger.toString()`.

#### 3.5.4 `SignaturePolicyIdentifier`

```xml
<xades:SignaturePolicyIdentifier>
  <xades:SignaturePolicyId>
    <xades:SigPolicyId>
      <xades:Identifier>urn:oid:2.16.724.1.3.1.1.2.1.9</xades:Identifier>   <!-- no Qualifier attribute -->
      <xades:Description>policyDescription or empty</xades:Description>
    </xades:SigPolicyId>
    <xades:SigPolicyHash>
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>G7roucf600+f03r/o0bAOQ6WAs0=</ds:DigestValue>
    </xades:SigPolicyHash>
    <xades:SigPolicyQualifiers>                                           <!-- only if policyQualifier -->
      <xades:SigPolicyQualifier><xades:SPURI>https://...pdf</xades:SPURI></xades:SigPolicyQualifier>
    </xades:SigPolicyQualifiers>
  </xades:SignaturePolicyId>
</xades:SignaturePolicyIdentifier>
```

Never `SignaturePolicyImplied` (OOXML uses it, section 8). Hash value is copied verbatim (not checked).
Known policies (afirma-core `policy.properties`, XAdES hashes):

| Name | Identifier | Hash alg | XAdES hash | Qualifier |
|---|---|---|---|---|
| FirmaAGE / FirmaAGE19 | `urn:oid:2.16.724.1.3.1.1.2.1.9` | `http://www.w3.org/2000/09/xmldsig#sha1` | `G7roucf600+f03r/o0bAOQ6WAs0=` | `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` |
| FirmaAGE18 | `urn:oid:2.16.724.1.3.1.1.2.1.8` | sha1 | `V8lVVNGDCPen6VELRD1Ja8HARFk=` | `https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf` |
| FacturaE 3.1 (section 4) | `http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf` | SHA1 | `Ohixl6upD6av8N7pEvDABhEL6hM=` | - |
| FacturaE 3.0 | `http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf` (with spaces) | SHA1 | `xmfh8D/Ec/hHeE1IB4zPd61zHIY=` | - |

#### 3.5.5 Production place and roles

```xml
<!-- EPES -->
<xades:SignatureProductionPlace>
  <xades:City/>? <xades:StateOrProvince/>? <xades:PostalCode/>? <xades:CountryName/>?
</xades:SignatureProductionPlace>
<xades:SignerRole><xades:ClaimedRoles><xades:ClaimedRole>r1</xades:ClaimedRole>...</xades:ClaimedRoles></xades:SignerRole>
<!-- B-Level -->
<xades:SignatureProductionPlaceV2>
  <xades:City/>? <xades:StreetAddress/>? <xades:StateOrProvince/>? <xades:PostalCode/>? <xades:CountryName/>?
</xades:SignatureProductionPlaceV2>
<xades:SignerRoleV2><xades:ClaimedRoles><xades:ClaimedRole>r1</xades:ClaimedRole>...</xades:ClaimedRoles></xades:SignerRoleV2>
```

The place element is emitted if at least one of the (4 or 5) params is non-null (empty strings count as
present and produce empty elements). Only the children whose param is non-null are written, in this
order. No CertifiedRoles / SignedAssertions are ever produced.

#### 3.5.6 `DataObjectFormat`

```xml
<xades:DataObjectFormat ObjectReference="#Reference-<u3>">
  <xades:Description/>                                  <!-- always, empty -->
  <xades:ObjectIdentifier>                              <!-- only if an OID applies -->
    <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
    <xades:Description/>                                <!-- always, empty -->
  </xades:ObjectIdentifier>
  <xades:MimeType>text/xml</xades:MimeType>             <!-- always -->
  <xades:Encoding/>                                     <!-- always; text = encoding or empty -->
</xades:DataObjectFormat>
```

`ObjectReference` and `Qualifier` are created with `setAttributeNS(<xades ns>, name)` but without a
prefix: they serialize and canonicalize as unqualified attributes (and re-parse as no-namespace
attributes). Rust: emit plain `ObjectReference="..."` / `Qualifier="..."`.

#### 3.5.7 `CommitmentTypeIndication`

```xml
<xades:CommitmentTypeIndication>
  <xades:CommitmentTypeId>
    <xades:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin</xades:Identifier>   <!-- Qualifier only if it starts with urn:oid: (never for the 6 URIs) -->
    <xades:Description>desc or empty</xades:Description>
    <xades:DocumentationReferences>                                                      <!-- only if any -->
      <xades:DocumentationReference>http://a.es/x</xades:DocumentationReference>
    </xades:DocumentationReferences>
  </xades:CommitmentTypeId>
  <xades:ObjectReference>#Reference-<u3></xades:ObjectReference>                         <!-- AllSignedDataObjects is never used by XAdES sign -->
  <xades:CommitmentTypeQualifiers>                                                       <!-- always, possibly empty -->
    <xades:CommitmentTypeQualifier>Q1</xades:CommitmentTypeQualifier>
  </xades:CommitmentTypeQualifiers>
</xades:CommitmentTypeIndication>
```

Placed after all `DataObjectFormat`s. Note the identifiers use the **v1.2.2** URIs regardless of
`xadesNamespace`.

### 3.6 KeyInfo (exact)

Default builder (`AOXMLAdvancedSignature.newKeyInfo`), children in this order:

1. `<ds:X509Data>` with one `<ds:X509Certificate>BASE64(DER)</ds:X509Certificate>` per certificate, in
   the given chain order (only `certChain[0]` with `includeOnlySignningCertificate=true`).
2. `<ds:KeyValue>` if `addKeyInfoKeyValue` (default true) **and the key is not EC**:
   `<ds:RSAKeyValue><ds:Modulus>B64</ds:Modulus><ds:Exponent>B64</ds:Exponent></ds:RSAKeyValue>`
   (big-endian unsigned, no leading zero byte; `AQAB` for 65537). DSA keys would give `DSAKeyValue`.
3. `<ds:KeyName>` if `addKeyInfoKeyName`: subject DN produced by `EscapeHelper.escapeLdapName` applied
   twice (net effect): RDNs in display order (most specific first), joined with `,` (no space), each
   `TYPE=value` where TYPE is the Java keyword (`CN`, `SURNAME`, `GIVENNAME`, `SERIALNUMBER`, `C`, ...,
   `OID.x.y.z` for unknown types), the value escaped once with `javax.naming.ldap.Rdn.escapeValue`
   (backslash before `, = + < > # ; " \` and leading/trailing space), and then these characters replaced
   by literal hex escapes: `á \C3\A1`, `é \C3\A9`, `í \C3\AD`, `ó \C3\B3`, `ú \C3\BA`, `Á \C3\81`,
   `É \C3\89`, `Í \C3\8D`, `Ó \C3\93`, `Ú \C3\9A`, `ñ \C3\B1`, `Ñ \C3\91`, `ç \C3\A7`, `Ç \C3\87`,
   `à \C3\A0`, `è \C3\A8`, `ì \C3\AC`, `ò \C3\B2`, `ù \C3\B9`, `À \C3\80`, `È \C3\88`, `Ì \C3\8C`,
   `Ò \C3\92`, `Ù \C3\99`, `ü \C3\BC`, `Ü \C3\9C`, `¿ \C2\BF`, `¡ \C2\A1`, `µ \C2\B5`, `º \C2\BA`,
   `ª \C2\AA`. Only the first AVA of a multi-valued RDN is kept. Example:
   `CN=EIDAS CERTIFICADO PRUEBAS - 99999999R,SURNAME=EIDAS CERTIFICADO,GIVENNAME=PRUEBAS,SERIALNUMBER=IDCES-99999999R,C=ES`.
4. `<ds:X509IssuerSerial>` **directly under KeyInfo** (not inside X509Data) if
   `addKeyInfoX509IssuerSerial`: `<ds:X509IssuerName>` = issuer DN escaped as in 3 (e.g.
   `CN=AC FNMT Usuarios,OU=Ceres,O=FNMT-RCM,C=ES`), `<ds:X509SerialNumber>` decimal.

`Id="<sigId>-KeyInfo"`. The KeyInfo reference (if present) digests the inclusive C14N of this element.

jxades' own builder (used only by cosign/countersign with `includeOnlySignningCertificate=true`, 3.11.5):
`<ds:KeyValue>` (always, also EC), then `<ds:X509Data>` with `<ds:X509Certificate>`,
`<ds:X509SubjectName>` = `getSubjectX500Principal().getName("RFC1779")` (e.g. `CN=EIDAS CERTIFICADO
PRUEBAS - 99999999R, OID.2.5.4.4=EIDAS CERTIFICADO, OID.2.5.4.42=PRUEBAS, OID.2.5.4.5=IDCES-99999999R, C=ES`),
`<ds:X509IssuerSerial><ds:X509IssuerName>getIssuerDN().getName()</ds:X509IssuerName>
<ds:X509SerialNumber>..</ds:X509SerialNumber></ds:X509IssuerSerial>`.

### 3.7 Id scheme summary

| Item | Id / URI |
|---|---|
| Signature | `Signature-<uuid>-Signature` (prefix `sigId = "Signature-<uuid>"`) |
| SignatureValue | `<sigId>-SignatureValue` |
| KeyInfo | `<sigId>-KeyInfo` |
| QualifyingProperties | `<sigId>-QualifyingProperties`, `Target="#<sigId>-Signature"` |
| SignedProperties | `<sigId>-SignedProperties` |
| SignedInfo, SignedProperties reference, KeyInfo reference, QP `ds:Object` | no Id |
| Data reference | `Reference-<uuid>` |
| Style reference | `StyleReference-<uuid>` |
| Enveloping data object | `Object-<uuid>`; style object `StyleObject-<uuid>` |
| Detached content | `CONTENT-<uuid>`; style `STYLE-<uuid>` |
| Wrapper root | `<RootXmlNodeName>-Root-<uuid>` (`AFIRMA-Root-<uuid>`) on sign; `AfirmaRoot-<uuid>` when cosign/countersign wrap a root Signature |
| Manifest | `Manifest-<uuid>`; its Object `ManifestObject-<uuidV3(referenceId)>`; SignedInfo reference to it `ManifestReference-<uuid>` (= `"Manifest" + referenceId`) |
| Manifest references | `Reference-<uuid>` each (or `referenceId` in the single-`uri` form) |
| Cosign data reference | `Reference-<uuid>` / `StyleReference-<uuid>`; enveloping copy `Object-<uuid>`; manifest copy `ManifestObject-<uuid>` + `Manifest-<uuid>` |

`uuidV3(x)` = `java.util.UUID.nameUUIDFromBytes(x.getBytes())`: MD5 of the bytes, version nibble 3,
IETF variant (no namespace prefix).

### 3.8 Digest values (closed forms; C = inclusive C14N 1.0 without comments unless the reference's C14N transform says otherwise)

| Reference | DigestValue = H(...) |
|---|---|
| Enveloping binary (`#base64`) | original bytes |
| Enveloping pre-encoded Base64 / `avoidBase64Transforms` | `C(<ds:Object xmlns:ds=".." Encoding=".." Id=".." MimeType="..">B64</ds:Object>)` |
| Enveloping XML | `C(ds:Object element)` including its attributes and the inherited `xmlns:ds` |
| Detached binary (`#base64`) | original bytes |
| Detached XML | `C(<CONTENT ...>..</CONTENT>)` (CONTENT has no namespace; ancestors declare none, except custom roots) |
| Detached/Enveloped `#nodeToSign` | `C(subtree of that element)` with inherited namespaces rendered on it (and, for Enveloped, Signature subtrees removed) |
| Enveloped `URI=""` | `C(document minus every ds:Signature subtree, minus comments)` (identical with or without the C14N+XPath transforms) |
| Externally detached | `data` verbatim (not a hash computed by AutoFirma) unless `data == null` (then file/http(s) dereferencing, 3.9.1) |
| Manifest reference | `C(ds:Manifest element)` with the C14N transform (`canonicalizationAlgorithm`) |
| SignedProperties | `C(xades:SignedProperties)` - its in-scope namespaces (`xmlns:ds`, `xmlns:xades`, plus any default/other namespace declared by ancestors such as an enveloped document root) are rendered on it |
| KeyInfo | `C(ds:KeyInfo)` |
| Countersignature | `C14N_param(ds:SignatureValue of the countersigned signature)` |

### 3.9 Externally Detached and Manifest

#### 3.9.1 Externally Detached (no manifest)

* `uri` mandatory. `DigestMethod` = `getDigestMethodByCommonName(precalculatedHashAlgorithm ?:
  referencesDigestMethod)` (SHA1/SHA-256/SHA-512 only).
* `data != null` (even empty): DigestValue = `data` bytes as is (see quirk in 3.2.1). The ASiC signer
  relies on this by passing the precomputed hash.
* `data == null`:
  * `uri` starts with `file://` (case-insensitive): read the file, hash with the *referencesDigestMethod*
    algorithm; reference with that digest.
  * `http://` / `https://`: GET the URL (afirma `UrlHttpManager`, with SSL error dialog support) and hash
    the raw bytes with the referencesDigestMethod algorithm.
  * otherwise: let Santuario dereference at signing time (normally fails).
  * Quirk: `uri` shorter than 7/8 chars throws `StringIndexOutOfBoundsException` in the prefix tests.
* No Transforms, no Type. The container is `<AFIRMA Id="AFIRMA-Root-..">` with only the Signature.
* `DataObjectFormat`: `MimeType` = `mimeType` param or `application/octet-stream` (no ObjectIdentifier
  unless `contentTypeOid` or a mime param maps to an OID).

#### 3.9.2 Manifest (`useManifest=true`)

1. References list: either the single `uri` form (DigestValue = `data`, Id = `Reference-<u3>`, MIME/OID/
   encoding from `mimeType`/`contentTypeOid`/`encoding`) or the numbered form (3.2.1), each with
   `Id="Reference-<uuid>"`, DigestMethod = `getDigestMethodByCommonName(precalculatedHashAlgorithm ?:
   referencesDigestMethod)`, DigestValue = the given digest; no Transforms, no Type.
2. `<ds:Manifest Id="Manifest-<uuid>">` holding those references, wrapped in
   `<ds:Object Id="ManifestObject-<uuidV3(Reference-<u3>)>">` (added before the QualifyingProperties
   object).
3. SignedInfo gets a single data reference: `<ds:Reference Id="ManifestReference-<u3-uuid>"
   Type="http://www.w3.org/2000/09/xmldsig#Manifest" URI="#Manifest-<uuid>">` with Transforms `[C14N]`
   (none if `none`), DigestMethod = referencesDigestMethod.
4. One `DataObjectFormat` per manifest reference (`ObjectReference="#<manifest ref Id>"`).
5. Manifest reference digests are never verified by AutoFirma (and generic validators do not check
   Manifest references by default).

### 3.10 XAdES-T (`XAdESTspUtil.timestampXAdES`) - sign only

Triggered when `new TsaParams(extraParams)` succeeds, i.e. `tsaURL` is present and is a valid URI (any
failure building TsaParams silently disables the timestamp). TsaParams keys: `tsaURL` (required),
`tsaPolicy` (default `0.4.0.2023.1.1`), `tsaHashAlgorithm` (default `SHA-512`, normalized with
`getDigestAlgorithmName`), `tsaRequireCert` (default true unless `"false"`), `tsaUsr`, `tsaPwd`,
`tsaSslKeyStore` (Base64), `tsaSslKeyStorePassword` (""), `tsaSslKeyStoreType` (`PKCS12`),
`tsaSslTrustStore` (Base64), `tsaSslTrustStorePassword` (""), `tsaSslTrustStoreType` (`PKCS12`),
`tsaExtensionOid` + `tsaExtensionValueBase64` (+ `tsaExtensionCritical`, default false) - a single
request extension only if both are present, `verifyHostname` (default true). The RFC 3161 request/
transport is the shared `CMSTimestamper` (see the CMS/TSP spec).

Algorithm:

1. Parse the signed XML. Take the first element `{http://uri.etsi.org/01903/v1.3.2#}QualifyingProperties`
   in document order (none -> `AOMalformedSignatureException`; >1 -> warning, first used). **Only the
   1.3.2 namespace is supported.**
2. `time` = the text of the first 1.3.2 `SigningTime` under it, parsed as `xs:dateTime` (if more than one,
   "now"). Passed to the timestamper.
3. Message imprint = `H_tsa( C14N_XOM( first ds:SignatureValue element of the document ) )` where the
   canonicalization is XOM's inclusive C14N 1.0 of that element **converted in isolation** (only its own
   namespace binding `xmlns:ds` is rendered, ancestors' other namespace declarations are not):
   `<ds:SignatureValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="...">B64</ds:SignatureValue>`.
   (For AutoFirma non-enveloped signatures this equals the standard inclusive C14N.)
4. Request a timestamp token (DER `ContentInfo`/SignedData) and Base64-encode it (no line breaks).
5. Append to the QualifyingProperties (always a **new** `UnsignedProperties`, even if one exists) the
   following fragment (namespace 1.3.2 hard-coded, including its whitespace text nodes):

```xml
<xades:UnsignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
 <xades:UnsignedSignatureProperties>
  <xades:SignatureTimeStamp>
   <ds:CanonicalizationMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
   <xades:EncapsulatedTimeStamp>
BASE64_TOKEN</xades:EncapsulatedTimeStamp>
  </xades:SignatureTimeStamp>
 </xades:UnsignedSignatureProperties>
</xades:UnsignedProperties>
```

   Exact Java literal (parsed, then imported into the signature document, so the inner whitespace text
   nodes are kept, the redundant `xmlns:xades` stays on `UnsignedProperties`, and the token text starts
   with `\n`):

   ```java
   "<xades:UnsignedProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">\n" +
   " <xades:UnsignedSignatureProperties>\n" +
   "  <xades:SignatureTimeStamp>\n" +
   "   <ds:CanonicalizationMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n" +
   "   <xades:EncapsulatedTimeStamp>\n" + tspTokenB64 + "</xades:EncapsulatedTimeStamp>\n" +
   "  </xades:SignatureTimeStamp>\n" +
   " </xades:UnsignedSignatureProperties>\n" +
   "</xades:UnsignedProperties>\n"
   ```

   No `Id` attributes; `SignatureTimeStamp` has no `Id`.
6. Re-serialize with the parsed document's encoding.

Not applied by cosign/countersign, nor by FacturaE (its params whitelist drops `tsa*`), nor by baseline
specially (B-Level + T = "T-Level" by detection).

### 3.11 Cosign (`XAdESCoSigner.cosign`)

#### 3.11.1 Preconditions (in `AOXAdESSigner.cosign`)

1. `isSign(doc)`.
2. `checkCompatibility(doc)`: for every signature node (root if it is a Signature, plus all descendant
   `ds:Signature` whose parent's local name is not `Timestamp`), for every descendant element with local
   name `QualifyingProperties` (any namespace): its namespace must be one of the 4 supported
   (`01903#`, 1.2.2, 1.3.2, 1.4.1) else `AOInvalidSignatureFormatException("... version inexistente de
   XAdES")`; all must share the same namespace else "... distintas versiones de XAdES"; `isBaselineEN`
   = (`QualifyingProperties/child[0]/child[0]/child[1]` has local name `SigningCertificateV2` in the same
   namespace) - any exception there -> `AOInvalidSignatureFormatException`. Note `child[n]` are raw DOM
   child nodes (whitespace text nodes count).
3. `checkSignProfile`: if `extraParams.get("confirmDifferentProfile") == Boolean.TRUE` and profiles
   differ -> UI question; else `profile := isBaselineEN ? "baseline" : "advanced"`.

#### 3.11.2 Algorithm

1. Params read: `referencesDigestMethod` (default SHA-512 URI), `canonicalizationAlgorithm` (default
   inclusive; no `none` support), `addKeyInfoKeyValue`, `addKeyInfoKeyName`,
   `addKeyInfoX509IssuerSerial`, `keepKeyInfoUnsigned` (default false, **not** forced by baseline),
   `outputXmlEncoding`, `contentTypeOid`, `mimeType`, `encoding` (base64 mapping + URI check),
   `validatePkcs1`, `profile`, `policy*`, production place, `signerClaimedRoles`,
   `includeOnlySignningCertificate`, `allowSignLTSignature`, `allowXadesEnvelopedWithoutXPath`,
   `avoidAGEPolicyIncompatibilities`. `xadesNamespace` / `signedPropertiesTypeUrl` are removed (warning).
   **No CommitmentTypeIndications, no xmlTransforms, no XAdES-T.**
2. If the root element's local name is `Signature`: wrap it in a new document
   `<AFIRMA Id="AfirmaRoot-<uuid>">` (note the different Id format) with the old root as only child.
3. ArchiveTimeStamp check (`allowSignLTSignature`, 3.2.4) over all `ds:Signature` descendants.
4. First signature = first `ds:Signature` (document order, or the root). From it: the SignedProperties
   reference (Reference whose `Type` is one of the 4 `...#SignedProperties` URIs) -> `signedPropertiesType`
   (default `http://uri.etsi.org/01903#SignedProperties` if empty) and the SignedProperties element ->
   `xadesNamespace` (its namespace; default 1.3.2). If `profile=baseline` but the namespace is not
   1.3.2/1.4.1 -> advanced.
5. `xmlsigPrefix` = prefix of the first `ds:Signature` element (used for the new signature and for
   parsing transforms).
6. For each data reference of the first signature (`getSignatureDataReferenceList`, 3.14.4), in order:
   * transforms = parsed copy of its `Transforms` (`Utils.getObjectReferenceTransforms`: finds child
     named `Transforms` or `<xmlsigPrefix>:Transforms`; for XPath takes the text of child `XPath` /
     `<prefix>:XPath` with namespace map `{prefix: dsig}`; XPath2 needs `Filter`; other algorithms without
     parameters - so exclusive C14N `InclusiveNamespaces` would be lost).
   * new Id: `StyleReference-<uuid>` if the original Id starts with `StyleReference-`, else
     `Reference-<uuid>`.
   * **Manifest** reference (`Type == ...#Manifest`): deep-clone the referenced `ds:Manifest` (must be a
     `#id` inside the first signature), copy the original `DataObjectFormat`s (parsed back with
     `DataObjectFormatParser`), give the clone a new `Id="Manifest-<uuid>"` and every inner Reference a
     new `Id="Reference-<uuid>"` (updating the copied DataObjectFormats' `ObjectReference`), wrap it in
     `<ds:Object Id="ManifestObject-<uuid>" [MimeType=mimeType] [Encoding=encoding]>`, add reference
     `URI="#Manifest-<new>" Type=...#Manifest` with the copied transforms. The copied DataObjectFormats
     are used as is.
   * **Enveloped** (`URI=""`): `mimeType := mimeType ?: "text/xml"`. If none of the copied transforms is
     an XPath whose expression contains `Signature` -> `allowXadesEnvelopedWithoutXPath` handling (3.2.4;
     when allowed, append XPath `not(ancestor-or-self::<prefix>:Signature)` with map `{prefix: dsig}`, or
     unprefixed `Signature` with an empty prefix). New reference `URI=""` with the copied transforms and
     `Type="http://www.w3.org/2000/09/xmldsig#Object"` (quirk: the original enveloped reference has no
     Type, the cosign one has `#Object`).
   * **Detached / Enveloping**: `dataNodeId` = URI without `#`. Search the data element: the root if its
     `Id` matches, else the root's children from last to first (and, for children named `Signature`,
     their children from last to first). If found: `mimeType := mimeType ?: @MimeType`, `encoding :=
     encoding ?: @Encoding` (missing attribute -> `""`). "Enveloping" if a direct child of the **first**
     signature has that Id.
     * Enveloping (AGE policy check first, 3.2.4): new `<ds:Object Id="Object-<uuid>" MimeType=..
       Encoding=..>` containing a deep clone of the **first child node** of the original Object (i.e. the
       Base64 text or the XML root), reference `URI="#Object-<uuid>"` with the copied transforms and the
       original Type. So each enveloping cosignature carries its own copy of the data.
     * Detached: reference to the same `URI` with the copied transforms and the original Type.
   * `DataObjectFormat` for non-manifest refs: OID = `contentTypeOid` or
     `MimeHelper.transformMimeTypeToOid(mimeType)` (**not** filtered: e.g. `text/plain` gets
     `urn:oid:1.2.840.113549.1.7.1`), MimeType = mimeType, Encoding = encoding.
   * Note `mimeType`/`encoding` variables carry over between iterations.
7. jxades instance with the existing namespace, prefixes `xades` / `xmlsigPrefix`, parent = root
   (**the new Signature is appended as last child of the document root**, also for enveloped documents
   where the original was inserted elsewhere), metadata (policy/place/roles), DataObjectFormats (only if
   non-empty), SignedProperties Type = copied one, SignedInfo C14N = `canonicalizationAlgorithm`.
8. Add the new Object (enveloping/manifest copy) before signing. Sign (3.4.7) with prefix
   `Signature-<uuid>`, or with jxades' base method if `includeOnlySignningCertificate` (3.11.5).
9. Output: `Utils.writeXML(root, props)` with the input's encoding (or `outputXmlEncoding`). The
   `AFIRMA` wrapper created in step 2 is kept.

#### 3.11.3 Resulting layouts

* Enveloping: `<AFIRMA Id="AfirmaRoot-<uuid>"><ds:Signature(original, with Object-A)/><ds:Signature(new,
  with Object-B = copy)/></AFIRMA>`.
* Detached: `<AFIRMA Id="AFIRMA-Root-.."><CONTENT/><ds:Signature/><ds:Signature/></AFIRMA>` - both
  reference `#CONTENT-..`.
* Enveloped: `<root>...<ds:Signature/><ds:Signature/></root>`.
* Externally detached / manifest: new Signature beside the old one under the root.

#### 3.11.4 Cosign of ASiC

See section 5 (`UriAndDataDereferencer` resolves the relative data URI).

#### 3.11.5 `includeOnlySignningCertificate=true` in cosign/countersign (quirk)

Calls jxades `XMLAdvancedSignature.sign(X509Certificate, key, method, refs, prefix)` instead of the
AutoFirma override. Differences: SignedInfo C14N always inclusive (param ignored); the KeyInfo reference
is always added (keepKeyInfoUnsigned ignored); KeyInfo = jxades builder (3.6, `KeyValue` first, X509Data
with certificate + `X509SubjectName` + `X509IssuerSerial`; addKeyInfo* ignored); no PKCS#1
self-verification; default Santuario dereferencer (no custom fallback).

### 3.12 Countersign (`XAdESCounterSigner`)

1. Params: `outputXmlEncoding`, `allowSignLTSignature` (message says countersigning archive signatures
   *might* invalidate them), plus per countersignature: `referencesDigestMethod`,
   `canonicalizationAlgorithm`, `validatePkcs1`, `profile` (default `advanced`, already forced by
   `checkSignProfile`), `includeOnlySignningCertificate`, `addKeyInfo*`, `keepKeyInfoUnsigned`, policy,
   place, roles. `MD*` rejected; unknown algorithm -> `IllegalArgumentException`.
2. If the root is a `Signature`: temporarily wrap in `<AFIRMA Id="AfirmaRoot-<uuid>">`; at the end the
   first `ds:Signature` is moved back to be the root (so a simple enveloping signature stays rooted at
   its Signature).
3. `signaturesList` = all `ds:Signature` descendants of the root (live list, document order, includes
   countersignatures; **not** filtering timestamp signatures).
4. Targets:
   * `TREE`: snapshot of all signatures; countersign each once (including existing countersignatures).
   * `LEAFS`: iterate the live list; a signature with no descendant `ds:Signature` is a leaf ->
     countersign, then skip the newly inserted one (i++, n++).
   * `NODES`: `targets` = `Integer` indexes into the list (duplicates removed; invalid index ->
     `AOException(INVALID_COUNTERSIGNATURE_INDEX)`).
   * `SIGNERS`: `targets` = CN strings; signatures whose **first** descendant `ds:X509Certificate` has a
     CN (`AOUtil.getCN`) contained in targets.
5. For each target signature S (`cs`):
   * SignedProperties element of S (via its SignedProperties reference; missing ->
     `AOMalformedSignatureException`); `xadesPrefix` = its prefix, `xadesNamespace` = its namespace,
     `signedPropertiesTypeUrl` = the reference's `Type`.
   * `UnsignedProperties` = first descendant of S with local name `UnsignedProperties` (any namespace),
     else a new element created with the **non-namespace-aware** `createElement("<prefix>:UnsignedProperties")`
     (serializes as `xades:UnsignedProperties`; prefix taken from an existing one if found). Same for
     `UnsignedSignatureProperties` inside it. A new `<prefix>:CounterSignature` is appended as **last
     child** of UnsignedSignatureProperties; UnsignedProperties is (re)appended as last child of the
     first `QualifyingProperties` of S.
   * Reference: `<ds:Reference Id="Reference-<uuid>" Type="http://uri.etsi.org/01903#CountersignedSignature"
     URI="#<Id of S's first ds:SignatureValue>">` with Transforms `[canonicalizationAlgorithm]` (default
     inclusive C14N) and DigestMethod = referencesDigestMethod. `Type` omitted when the XAdES namespace is
     1.1.1 or 1.2.2.
   * jxades instance: profile (baseline only if namespace 1.3.2/1.4.1), namespace = S's, xades prefix =
     S's, ds prefix `ds`, parent = the `CounterSignature` element (the new `ds:Signature` becomes its
     child).
   * Metadata (policy/place/roles). `DataObjectFormat` only when not baseline (EN 319 132-1 6.3 k):
     `ObjectReference="#Reference-<uuid>"`, ObjectIdentifier `urn:oid:1.2.840.10003.5.109.10`
     (`OIDAsURN`), `MimeType` `text/xml`, `Encoding` = the parser's detected input encoding of the
     document (`Document.getInputEncoding()`, e.g. `UTF-8`; **empty** when the input root was a
     Signature, because the wrapper document has none). No CTIs.
   * Sign with prefix `Signature-<uuid>` (3.4.7 / 3.11.5). Baseline does **not** force
     `keepKeyInfoUnsigned` here.
6. Output encoding: `outputXmlEncoding` or the input's.

Resulting structure (real output, base64 elided):

```xml
<ds:Signature Id="Signature-A-Signature"> ...
  <ds:Object><xades:QualifyingProperties ...>
    <xades:SignedProperties Id="Signature-A-SignedProperties">...</xades:SignedProperties>
    <xades:UnsignedProperties>
      <xades:UnsignedSignatureProperties>
        <xades:CounterSignature>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-B-Signature">
            <ds:SignedInfo>
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference Id="Reference-.." Type="http://uri.etsi.org/01903#CountersignedSignature" URI="#Signature-A-SignatureValue">
                <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/><ds:DigestValue>..</ds:DigestValue>
              </ds:Reference>
              <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-B-SignedProperties">..</ds:Reference>
              <ds:Reference URI="#Signature-B-KeyInfo">..</ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue Id="Signature-B-SignatureValue">..</ds:SignatureValue>
            <ds:KeyInfo Id="Signature-B-KeyInfo">..</ds:KeyInfo>
            <ds:Object><xades:QualifyingProperties xmlns:xades=".." xmlns:ds=".." Id="Signature-B-QualifyingProperties" Target="#Signature-B-Signature">
              <xades:SignedProperties Id="Signature-B-SignedProperties">
                <xades:SignedSignatureProperties><xades:SigningTime/>..<xades:SigningCertificate/>..</xades:SignedSignatureProperties>
                <xades:SignedDataObjectProperties>
                  <xades:DataObjectFormat ObjectReference="#Reference-..">
                    <xades:Description/>
                    <xades:ObjectIdentifier><xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier><xades:Description/></xades:ObjectIdentifier>
                    <xades:MimeType>text/xml</xades:MimeType>
                    <xades:Encoding>UTF-8</xades:Encoding>   <!-- empty if the input root was the Signature -->
                  </xades:DataObjectFormat>
                </xades:SignedDataObjectProperties>
              </xades:SignedProperties>
            </xades:QualifyingProperties></ds:Object>
          </ds:Signature>
        </xades:CounterSignature>
      </xades:UnsignedSignatureProperties>
    </xades:UnsignedProperties>
  </xades:QualifyingProperties></ds:Object>
</ds:Signature>
```

A second countersignature of the same signature adds another `xades:CounterSignature` inside the same
UnsignedSignatureProperties.

### 3.13 Signers structure (`getSignersStructure`)

1. `isSign` else `AOInvalidSignatureFormatException`.
2. Collect all `ds:Signature` in document order (descendants of the document; root included), skipping
   those whose parent local name is `Timestamp`. For each: `id = @Id`; node label =
   `asSimpleSignInfo ? Utils.getSimpleSignInfoNode(ns, sig) : CN of its first descendant X509Certificate`
   where `ns` = namespace of the **first signature's** SignedProperties (section 11 describes
   `AOSimpleSignInfo`: SigningTime parsed with `yyyy-MM-dd'T'HH:mm:ss` ignoring the offset, all descendant
   certificates, SignatureMethod URI, first SignatureValue bytes).
3. `ref` = "" for signatures whose parent local name is not `CounterSignature`; otherwise
   `Utils.getCounterSignerReferenceId`: URI (minus first char) of the first descendant `ds:Reference`,
   matched against the `Id` of all `ds:SignatureValue` elements -> the `Id` of that SignatureValue's parent
   (the countersigned Signature).
4. Root node `"Datos"`; each signature with `ref == ""` is a child of the root; each countersignature is a
   child of the signature whose `@Id` equals its `ref` (children in document order). The Java code
   builds this with the recursive `generateSignsTree(i, n-1, ...)`, which is the same algorithm as
   XMLdSig's `generaArbol` (pseudo-code and `AOTreeNode.add` move semantics in section 6); for normal
   documents the result is the parent relation above, but port the recursion literally if exact sibling
   order in exotic documents matters.

Example (sign + countersign TREE twice): `Datos -> [S1 -> [CS1 -> [CS1'], CS2]]`.

### 3.14 Detection helpers, getSignInfo, getData

#### 3.14.1 `isSign(Document)`

* `signNodes` = [root if root local name is `Signature` (any namespace!)] + every
  `{xmldsig}Signature` descendant whose parent local name is not `Timestamp`.
* Empty -> false. Every sign node must have, among its descendants, at least one
  `QualifyingProperties` in one of `http://uri.etsi.org/01903#`, `.../v1.2.2#`, `.../v1.3.2#`,
  `.../v1.4.1#` (1.1.1 is NOT accepted here) -> otherwise false. Any exception -> false.
* So a document with a plain XMLDSig signature next to a XAdES one is not a XAdES signature.

#### 3.14.2 Variant detection (on the first signature = root if `Signature`, else first `ds:Signature` descendant)

Data references (`getSignatureDataReferenceList`, 3.14.4) are classified, in this order:

1. Enveloped: any data reference with a Transform `enveloped-signature`, or an XPath transform whose
   text (all whitespace removed) equals `not(ancestor-or-self::P:Signature)` or
   `count(ancestor-or-self::P:Signature|here()/ancestor::P:Signature[1])>count(ancestor-or-self::P:Signature)`
   where P = the signature element's prefix -> `XAdES Enveloped`.
2. Externally detached: any data reference URI starting (case-insensitive) with `http://` or `https://`
   -> `XAdES Externally Detached`.
3. Internally detached: any `#id` data reference that resolves (exact `Id`) to an element of the
   document **outside** any element whose local name is `Signature` -> `XAdES Detached`.
4. Enveloping: any `#id` data reference resolving inside the signature element -> `XAdES Enveloping`.
5. Otherwise no variant (e.g. ASiC relative URIs, `urn:` URIs).

Manifest signatures are reported as Enveloping (the `#Manifest-..` is inside the signature).
`isManifestSignature` = some data reference has `Type="http://www.w3.org/2000/09/xmldsig#Manifest"`.

#### 3.14.3 `getData(sign)`

Parse; not `isSign` -> `AOInvalidSignatureFormatException`. First signature, its data references:

* Externally detached or manifest -> `null` (never dereferenced, by design).
* Enveloped: referenced element (`URI=""` -> root; `#id` -> element with exact `Id`; other -> null,
  later NPE -> exception). Remove its **direct** child `Signature` elements (local name), repeatedly.
  If the referenced element is not the root and its first child is a text node: return its text
  (Base64-decoded if the reference declares the `#base64` transform). Else serialize the element
  (`Utils.writeXML`, UTF-8 with XML declaration; attributes re-ordered).
* Internally detached: **assumes the first child of the root is the data element** (CONTENT): if its
  first child is text -> text (decoded if a reference to `#<its Id>` declares `#base64`), else the XML of
  its first child.
* Enveloping: the **first `ds:Object` of the document**: if its `MimeType` is exactly `text/xml` -> XML
  of its first child; else its text, decoded if the reference to `#<Object Id>` declares `#base64`
  (so pre-encoded Base64 data returns the Base64 text bytes).
* Unknown -> null. Any exception -> `AOInvalidSignatureFormatException`.

#### 3.14.4 Data references of a signature (`getSignatureDataReferenceList`)

From the signature's own `ds:SignedInfo` (direct child), all `ds:Reference` descendants: keep those
whose `Type` is non-empty and not one of the 4 SignedProperties types
(`http://uri.etsi.org/01903#SignedProperties`, `.../v1.2.2#SignedProperties`,
`.../v1.3.2#SignedProperties`, `.../v1.4.1#SignedProperties`); for references without Type keep them
unless their `#id` resolves inside the signature to an element named `KeyInfo` or `SignedProperties`.
Non-`#` URIs are kept.

### 3.15 Error codes used (XAdES/XML)

| Code | Constant | When |
|---|---|---|
| 213001 | `XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR` | generic signing failure, PKCS#1 self-check failure |
| 213002 | `INTERNAL_XML_SIGNING_ERROR` | DOM/transform construction errors |
| 610001 | `INVALID_ENCODING_URI` | `encoding` not a URI |
| 610002 | `INVALID_REFERENCES_HASH_ALGORITHM_URI` | bad `referencesDigestMethod` |
| 610003 | `INVALID_CANONICALIZATION_URI` | bad `canonicalizationAlgorithm` |
| 610004 | `INVALID_PRECALCULATED_DATA_HASH_ALGORITHM` | bad `precalculatedHashAlgorithm` |
| 610005 | `INVALID_TRANSFORMATION` | cosign transform parsing |
| 610006 | `INVALID_REFERENCE_URI` | manifest reference creation |
| 610007 | `INVALID_NODE_SELECTOR_XPATH` | `insertEnvelopedSignatureOnNodeByXPath` |
| 411001 | `DERREFERENCING_DATA_ERROR` | download of external data failed |
| 501011 | `XPATH_NOT_FOUND` | enveloped cosign without XPath and `allowXadesEnvelopedWithoutXPath=false` |
| 510002 | `XML_DOCUMENT_NEEDED` | Enveloped/nodeToSign with non-XML data (`InvalidXMLException`) |
| 610201..610204 | `XAdESErrorCode.Request.*` | manifest hash missing / bad Base64 / no references / bad data URI |
| 510008 / 510009 | `XAdESErrorCode.Functional.FACTURAE_ALREADY_SIGNED` / `FACTURAE_NEEDED` | FacturaE |

---

## 4. FacturaE signer (`AOFacturaESigner`)

Format names: `FacturaE` (also `Factura-e`; tri-phase `FacturaEtri`). A thin wrapper over
`AOXAdESSigner`:

* `isValidDataFile(data)`: parses (`Utils.getNewDocumentBuilder`) and requires root local name
  `Facturae` (any namespace, so FacturaE 3.0 `http://www.facturae.es/Facturae/2007/v3.0/Facturae`,
  3.1 `.../2009/v3.1/Facturae`, 3.2/3.2.1/3.2.2 `.../2009/v3.2/Facturae`, `.../2014/v3.2.1/Facturae`
  are all accepted) and, among its **direct children**, elements with local names `FileHeader`,
  `Parties` and `Invoices`. No schema validation, no version check.
* `isSign(data)` = `isValidDataFile && AOXAdESSigner.isSign`.
* `sign(data, alg, key, chain, params)`: not a valid invoice -> `InvalidEFacturaDataException`
  (510009); already signed -> `EFacturaAlreadySignedException` (510008); else
  `AOXAdESSigner.sign(data, alg, key, chain, getFacturaEExtraParams(params))`.
* `cosign` / `countersign` -> `UnsupportedOperationException("No se soporta la cofirma de facturas" /
  "... contrafirma ...")`.
* `getSignersStructure`, `getData`, `getSignedName` (`.xsig`) delegate to XAdES; `getSignInfo` returns
  `AOSignInfo("FacturaE")` with null variant (no parsing).

`getFacturaEExtraParams(original)`:

1. Start from fixed params `format = "XAdES Enveloped"`, `facturaeSign = "true"`.
2. If `original == null`: return just that (quirk: **no policy and no signer role** are added).
3. Else (the caller's Properties object is modified in place!):
   * `signerClaimedRoles` = lower-cased value, default `emisor`; must be one of `emisor`, `receptor`,
     `tercero`, `supplier`, `customer`, `third party` -> else `IllegalArgumentException`.
   * Policy: if `policyIdentifier` is present, `new AdESPolicy(id, hash, hashAlg, qualifier)` must equal
     (identifier, hash, normalized hash algorithm) FacturaE 3.1 or 3.0 (table in 3.5.4) else
     `IllegalArgumentException("La politica no esta soportada ...")`. If absent: remove `policyQualifier`
     and put FacturaE 3.1: `policyIdentifier`, `policyIdentifierHash=Ohixl6upD6av8N7pEvDABhEL6hM=`,
     `policyIdentifierHashAlgorithm=SHA1` (no qualifier, no description).
     (`AdESPolicy` with a null/`"0"` hash would download the identifier URL and hash it with SHA-512 by
     default - only reachable with a user-supplied FacturaE policy without hash.)
   * Copy only these keys from `original`: `signatureProductionCity`, `signatureProductionProvince`,
     `signatureProductionPostalCode`, `signatureProductionCountry`, `xadesNamespace`,
     `signedPropertiesTypeUrl`, `policyIdentifier`, `policyIdentifierHash`,
     `policyIdentifierHashAlgorithm`, `policyDescription`, `policyQualifier`, `signerClaimedRoles`,
     `SignatureId`. Everything else (digest method, C14N, profile, KeyInfo options, tsa*, ...) is
     dropped, so FacturaE always uses: SHA-512 references, inclusive C14N SignedInfo, EPES profile,
     full chain + KeyValue, KeyInfo signed, namespace 1.3.2 unless overridden.

Resulting structure (real output, invoice `facturae_32v1.xml`):

* The Signature is appended as last child of the `fe:Facturae` root (after `Invoices`).
* Data reference: `<ds:Reference Id="Reference-<uuid>" URI="">` with **only**
  `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` (no C14N, no
  XPath; `URI="#<id>"` if the Facturae root had an `Id` attribute), DigestMethod SHA-512.
* SignedProperties: SigningTime, SigningCertificate, SignaturePolicyIdentifier (FacturaE 3.1, empty
  Description, no qualifiers), [SignatureProductionPlace], SignerRole/ClaimedRoles/ClaimedRole `emisor`;
  DataObjectFormat `text/xml` + `urn:oid:1.2.840.10003.5.109.10`.
* Namespaces declared by the invoice root stay on it (e.g. `xmlns:ds` already declared by the input is
  kept, and Santuario still declares `xmlns:ds` on `ds:Signature`).

---

## 5. ASiC-S XAdES signer (`asic.AOXAdESASiCSSigner`)

Format `XAdES-ASiC-S` (tri-phase `XAdES-ASiC-S-tri`). Container helper `afirma-core ASiCUtil`.

Extra parameter: `asicsFilename` - name of the data entry inside the container. Default
`"dataobject." + MimeHelper(data).getExtension()` (fallback extension `bin`; e.g. `hello world` ->
`dataobject.txt`).

`setASiCProperties(params, data)` (mutates and returns `params`): sets `addKeyInfoKeyName=true`,
`uri=<data entry name>`, `RootXmlNodeName=asic:XAdESSignatures`,
`RootXmlNodeNamespace=http://uri.etsi.org/02918/v1.2.1#`, `RootXmlNodeNamespacePrefix=xmlns:asic`.

* `sign(data, ...)`: params = setASiCProperties + `keepKeyInfoUnsigned=true` + `format=XAdES Externally
  Detached`; digest = `H(data)` with `getDigestAlgorithmName(precalculatedHashAlgorithm ?:
  referencesDigestMethod ?: SHA-512 URI)`; `AOXAdESSigner.sign(digest, ...)` -> since data is the digest,
  the Reference is `<ds:Reference Id="Reference-<uuid>" URI="dataobject.txt">` with that digest (no
  Type/Transforms). Signature document root:
  `<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" Id="asic:XAdESSignatures-Root-<uuid>">`.
  KeyInfo = X509Data(chain) + KeyValue + KeyName; no KeyInfo reference. XAdES-T is applied if `tsaURL`.
* Container (`ASiCUtil.createSContainer(sig, data, "META-INF/signatures.xml", asicsFilename)`), Java
  `ZipOutputStream`, all entries **DEFLATED** (including `mimetype`, which ASiC requires STORED -
  quirk), entry order: `mimetype` (content `application/vnd.etsi.asic-s+zip`, no newline), data entry,
  `META-INF/signatures.xml`; ZIP archive comment `mimetype=application/vnd.etsi.asic-s+zip`; entry
  times = now.
* `cosign(sign)`: extract `META-INF/signatures.xml` and the first data entry (any entry other than
  `mimetype`, `META-INF/signature.p7s`, `META-INF/signatures.xml`; name = basename); params =
  setASiCProperties(data) + `keepKeyInfoUnsigned=true`; XAdES cosign with an `UriAndDataDereferencer`
  mapping `<data name> -> bytes` (so the copied relative reference is digested over the data); repack
  with the same data name. The new Signature is appended under `asic:XAdESSignatures`.
* `countersign`: same extraction; XAdES countersign (no special dereferencer needed); repack.
* `getSignersStructure`, `getSignInfo` -> XAdES on `META-INF/signatures.xml`; `isSign` = that entry exists
  and `AOXAdESSigner.isSign` on it; `getData` = first data entry; `isValidDataFile` = `data != null`;
  `getSignedName` = `name + inText + ".asics"`. Size guard: inputs >= 1 GB rejected.

---

## 6. XMLdSig signer (`AOXMLDSigSigner`)

Module `afirma-crypto-xmlsignature`, package `es.gob.afirma.signers.xmldsig`:

| File | Role |
|---|---|
| `AOXMLDSigSigner.java` (2461 lines) | The signer (`implements AOSigner`). Holds *instance state* (`algo`, `doc`) used by countersign / signers-structure, so one instance is not thread-safe. |
| `AOXMLDSigExtraParams.java` | extraParam key constants (package-private). |
| `XmlDSigUtil.java` | `cleanReferencesList()` (strips Base64 transforms from id-less references) and `guessXmlDSigNamespacePrefix()`. |
| `CustomUriDereferencer.java` | Fallback URI dereferencer used when the JSR-105 default one fails (identical in spirit to the one in core-xml). |

It relies on `afirma-crypto-core-xml` (`Utils`, `XMLConstants`, `XmlStyle`, `XmlDSigProviderHelper`) and on JSR-105 (`javax.xml.crypto.dsig`) as implemented by Apache Santuario (`org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI`, forced to first provider position by `XmlDSigProviderHelper.configureXmlDSigProvider()` in the class static initializer). The only use of the external jxades library is `es.uji.crypto.xades.jxades.util.DOMOutputImpl` (a trivial `LSOutput` bean) in the private `writeXML(Writer, Node)` helper.

All the behaviour below was confirmed by compiling the real Java sources (afirma-core + afirma-crypto-core-xml + afirma-crypto-xmlsignature, Apache Santuario xmlsec 3.0.5, JDK 21) and running the signer; every "Example" is real output (only long Base64 blobs are elided with `…` unless stated "complete"), and every produced signature was checked with a JSR-105 validator.

### Constants

```text
Format names (AOSignConstants)                       Mode names
  "XMLDSig"                     (generic, getSignInfo)   "implicit"  (SIGN_MODE_IMPLICIT)  <- XMLdSig default
  "XMLDSig Detached"                                      "explicit"  (SIGN_MODE_EXPLICIT)
  "XMLDSig Externally Detached"
  "XMLDSig Enveloped"
  "XMLDSig Enveloping"          <- default format

Private constants in AOXMLDSigSigner
  XADESNS        = "http://uri.etsi.org/01903#"          (only used to look for SigningTime in getSignersStructure)
  CSURI          = "http://uri.etsi.org/01903#CountersignedSignature"   (Type of countersignature reference)
  AFIRMA         = "AFIRMA"                               (wrapper root element, no namespace)
  XML_SIGNATURE_PREFIX = "ds"                             (default prefix)
  DETACHED_CONTENT_ELEMENT_NAME = "CONTENT"
  DETACHED_STYLE_ELEMENT_NAME   = "STYLE"
  STYLE_REFERENCE_PREFIX        = "StyleReference-"
  DIGEST_METHOD  = DigestMethod.SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"   (default referencesDigestMethod)

XMLConstants (core-xml)
  DSIGNNS          = "http://www.w3.org/2000/09/xmldsig#"
  OBJURI           = "http://www.w3.org/2000/09/xmldsig#Object"   (Type of every data/style Reference)
  BASE64_ENCODING  = "http://www.w3.org/2000/09/xmldsig#base64"
  DEFAULT_MIMETYPE = "application/octet-stream"

JSR-105 URIs used
  C14N inclusive (default)  http://www.w3.org/TR/2001/REC-xml-c14n-20010315
  enveloped-signature       http://www.w3.org/2000/09/xmldsig#enveloped-signature
  XPath 1.0 filter          http://www.w3.org/TR/1999/REC-xpath-19991116
  XPath Filter 2.0          http://www.w3.org/2002/06/xmldsig-filter2
  Base64 transform          http://www.w3.org/2000/09/xmldsig#base64
  EC KeyValue namespace     http://www.w3.org/2009/xmldsig11#
```

`SignatureMethod` URI comes from `XMLConstants.SIGN_ALGOS_URI` (exact-string lookup; anything else -> `AOException` code `600107` "algorithm not supported", e.g. `MD5withRSA`, `SHA1withDSA`):

| Accepted algorithm names | SignatureMethod Algorithm |
|---|---|
| `SHA1withRSA`, `RSA`, `SHA-1withRSA`, `SHA1withRSAEncryption`, `SHA-1withRSAEncryption`, `SHAwithRSAEncryption`, `SHAwithRSA` | `http://www.w3.org/2000/09/xmldsig#rsa-sha1` |
| `SHA256withRSA`, `SHA-256withRSA`, `SHA256withRSAEncryption`, `SHA-256withRSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` |
| `SHA384withRSA`, `SHA-384withRSA`, `SHA384withRSAEncryption`, `SHA-384withRSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha384` |
| `SHA512withRSA`, `SHA-512withRSA`, `SHA512withRSAEncryption`, `SHA-512withRSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512` |
| `SHA1withECDSA`, `ECDSA`, `SHA-1withECDSA`, `SHA1withECDSAEncryption`, `SHA-1withECDSAEncryption`, `SHAwithECDSAEncryption`, `SHAwithECDSA` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1` |
| `SHA224withECDSA`, `SHA-224withECDSA`, `SHA224withECDSAEncryption`, `SHA-224withECDSAEncryption` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224` |
| `SHA256withECDSA`, … (same 4 variants) | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` |
| `SHA384withECDSA`, … | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384` |
| `SHA512withECDSA`, … | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512` |

RSA SignatureValue = RSASSA-PKCS1-v1_5; ECDSA SignatureValue = raw `r || s` (each left-padded to the curve byte length, 64 bytes total for P-256), *not* DER (standard XMLDSig rule applied by JSR-105).

`referencesDigestMethod` must be a JSR-105 DigestMethod URI (names like `SHA-256` are rejected with `AOException` `610002`). Santuario accepts: `http://www.w3.org/2000/09/xmldsig#sha1`, `http://www.w3.org/2001/04/xmldsig-more#sha224`, `http://www.w3.org/2001/04/xmlenc#sha256`, `http://www.w3.org/2001/04/xmldsig-more#sha384`, `http://www.w3.org/2001/04/xmlenc#sha512`, `http://www.w3.org/2001/04/xmlenc#ripemd160`, and the SHA-3 URIs `http://www.w3.org/2007/05/xmldsig-more#sha3-{224,256,384,512}`.

`canonicalizationAlgorithm` must be a JSR-105 C14N URI: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` (default), `…-20010315#WithComments`, `http://www.w3.org/2001/10/xml-exc-c14n#`, `…#WithComments`, `http://www.w3.org/2006/12/xml-c14n11`, `…#WithComments`; plus the magic value `none` (case-insensitive, `sign()` only). Invalid URI -> `AOException` `610003`.

### Public API

| Method | Behaviour (summary; details below) |
|---|---|
| `byte[] sign(byte[] data, String algorithm, PrivateKey key, Certificate[] certChain, Properties xParams)` | Creates one `ds:Signature` in the selected format. |
| `byte[] cosign(byte[] data, byte[] sign, String algorithm, PrivateKey, Certificate[], Properties)` | Adds an independent sibling `ds:Signature` re-signing the data references of the *first* signature. `data` is ignored. |
| `byte[] cosign(byte[] sign, String algorithm, PrivateKey, Certificate[], Properties)` | Builds a "data" document (clone without signatures, unused) and delegates to the 6-arg `cosign`. |
| `byte[] countersign(byte[] sign, String algorithm, CounterSignTarget targetType, Object[] targets, PrivateKey, Certificate[], Properties)` | Adds sibling `ds:Signature`s whose single data reference points to `#SignatureValue-…` of the countersigned signature (`Type=CSURI`). Target types `TREE`, `LEAFS`, `NODES`, `SIGNERS`. |
| `AOTreeModel getSignersStructure(byte[] sign, boolean asSimpleSignInfo)` / `(byte[], Properties, boolean)` | Tree rooted at `"Datos"`; children = top-level signatures; countersignatures nested. Returns `null` (no exception) when the XML cannot be parsed. `params` ignored. |
| `boolean isSign(byte[])` / `(byte[], Properties)` | `true` iff the bytes parse as XML and contain at least one element `{http://www.w3.org/2000/09/xmldsig#}Signature` anywhere (including root). `params` ignored. |
| `boolean isValidDataFile(byte[] data)` | `data != null` (anything can be signed). |
| `byte[] getData(byte[])` / `(byte[], Properties)` | Extracts signed content for detached (internal), enveloped and enveloping signatures. |
| `String getSignedName(String originalName, String inText)` | `originalName + (inText != null ? inText : "") + ".xsig"` |
| `AOSignInfo getSignInfo(byte[])` / `(byte[], Properties)` | `new AOSignInfo("XMLDSig")` with variant `XMLDSig Detached` / `XMLDSig Enveloped` / `XMLDSig Enveloping` (checked in that order). Throws `IllegalArgumentException` on null input, `AOInvalidSignatureFormatException` if `!isSign`. |

Detection order in `AOSignerFactory.getSigner(byte[])`: FacturaE and XAdES signers are tried **before** XMLdSig, so XMLdSig's very permissive `isSign` (true for *any* XML containing a `ds:Signature`, including XAdES) only wins when the XAdES signers reject the input.

### extraParams

All values are `String`s in a `java.util.Properties`. Booleans are parsed with `Boolean.parseBoolean` (only a case-insensitive `"true"` is true). `null` `xParams` == empty.

| Key | Type / allowed values | Default | Applies to | Effect |
|---|---|---|---|---|
| `format` | `XMLDSig Enveloping` \| `XMLDSig Detached` \| `XMLDSig Enveloped` \| `XMLDSig Externally Detached` | `XMLDSig Enveloping` | sign | Signature format. **Validated case-insensitively, but every later branch uses case-sensitive `equals`**: a differently-cased value (e.g. `xmldsig enveloping`) passes validation and then matches no branch, producing an `AFIRMA`-rooted document whose only Reference is the KeyInfo one (the data is not signed nor included). |
| `mode` | `implicit` \| `explicit` | `implicit` | sign | Implicit = embed/sign the data; explicit = sign a hash of the data. Same case-sensitivity trap: `IMPLICIT` validates but is treated as explicit (`mode.equals("implicit")` false). |
| `uri` | URI string (parsed with `AOUtil.createURI`: `\`->`/`, unsafe chars percent-encoded, schemes `http`,`https`,`file`,`urn`; scheme-less or drive-letter paths become `file://…`) | none | sign | Externally detached: location of the data. Explicit mode: data to hash is read from this URI instead of `data`. Unparseable values are silently ignored (`uri = null`). |
| `precalculatedHashAlgorithm` | hash name (`SHA1`, `SHA-256`, `SHA-512`, `RIPEMD160`, or anything `AOSignConstants.getDigestAlgorithmName` maps to those) | none | sign | `data` is already a digest. Explicit mode: put `data` as the hash (MimeType `hash/<value.toLowerCase()>`). Externally detached: the reference DigestValue is `data` itself (only SHA1 / SHA-256 / SHA-512 / RIPEMD160 accepted; SHA-384 -> `AOException` `610004`). |
| `referencesDigestMethod` | DigestMethod URI (see list above) | `http://www.w3.org/2000/09/xmldsig#sha1` | sign, cosign, countersign | DigestMethod of every Reference (except the precalculated-hash externally-detached one). Note the default is SHA-1, unlike XAdES (`DigestMethod.SHA512`). |
| `canonicalizationAlgorithm` | C14N URI, or `none` (sign only) | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | sign, cosign, countersign | Used both as SignedInfo `CanonicalizationMethod` and as a Reference transform (see per-format rules). `none`: no C14N transform is added to references, and `CanonicalizationMethod` falls back to inclusive C14N. In cosign/countersign `none` is not special -> `UnsupportedOperationException("Hay al menos un algoritmo no soportado…")`. |
| `xmlSignaturePrefix` | any NCName, or `""` | `ds` | sign, cosign, countersign | Prefix bound to `http://www.w3.org/2000/09/xmldsig#` in the produced Signature (`""` -> default namespace `xmlns="…xmldsig#"`). Also used inside the enveloped XPath expression and as the XPath namespace map key. (XMLdSig-only key; it is not in `XAdESExtraParams`.) |
| `ignoreStyleSheets` | boolean | `false` | sign (implicit, XML data) | `true`: do not look at `<?xml-stylesheet?>` at all (the PI is then lost from enveloped output, see Style sheets). |
| `avoidBase64Transforms` | boolean | `false` | sign | `true`: when binary data was Base64-encoded by the signer, do **not** declare the `#base64` transform (the reference then digests the canonicalized `Object`/`CONTENT` element). |
| `headless` | boolean | **`true`** (code default `Boolean.TRUE`) | sign | `false` allows Swing dialogs to locate a `file://` style sheet. Rust CLI: treat as always headless. |
| `avoidXpathExtraTransformsOnEnveloped` | boolean | `false` | sign (Enveloped) | `true`: omit the `not(ancestor-or-self::ds:Signature)` XPath transform (only `enveloped-signature` remains). Breaks later cosign validity of the first signature. |
| `mimeType` | MIME string | auto | sign | XML data: used if present and != `application/octet-stream`, else `text/xml`. Binary data: kept unless it is `application/octet-stream`/absent (then auto-detected with `MimeHelper`); **ignored and re-detected** when the data is treated as pre-encoded Base64. Written as `MimeType` attribute of `ds:Object`/`CONTENT`. |
| `encoding` | charset name, or `base64` (any case, mapped to `http://www.w3.org/2000/09/xmldsig#base64`) or the base64 URI | XML declaration encoding of the data | sign, countersign | sign/XML: `Encoding` attribute and **output charset** of the signature document (unless it is the base64 URI). sign/binary: overwritten with the base64 URI. countersign: forces the output charset (default: input document's declared encoding). |
| `includeOnlySignningCertificate` | boolean (note the misspelling) | `false` | sign, cosign, countersign | `true`: `X509Data` contains only `certChain[0]`; otherwise the whole `certChain` in the given order. |
| `xmlTransforms` | integer as string | `0` | sign | Number of custom transforms. Non-numeric -> `NumberFormatException` propagates (unchecked). |
| `xmlTransform<N>Type` (N = 0 … xmlTransforms-1) | `http://www.w3.org/TR/1999/REC-xpath-19991116` \| `http://www.w3.org/2002/06/xmldsig-filter2` \| `http://www.w3.org/2000/09/xmldsig#base64` \| `http://www.w3.org/2000/09/xmldsig#enveloped-signature` | — | sign | Transform algorithm. Any other value: warning, skipped. XPath / XPath2 without a `Body`: skipped. |
| `xmlTransform<N>Subtype` | `subtract` \| `intersect` \| `union` (case-sensitive) | — | sign | XPath Filter 2.0 filter type; other values -> skipped. |
| `xmlTransform<N>Body` | XPath expression text | — | sign | XPath: `new XPathFilterParameterSpec(body, {xmlSignaturePrefix -> dsig-ns})`. XPath2: `new XPathFilter2ParameterSpec([XPathType(body, filter)])`. |

Parameters that exist for XAdES (`nodeToSign`, `useManifest`, policies, roles, `insertEnvelopedSignatureOnNodeByXPath`, …) are ignored by this signer.

### sign(): parameter validation

1. `algoUri = SIGN_ALGOS_URI.get(algorithm)`; null -> `AOException("Los formatos de firma XML no soportan el algoritmo de firma …", 600107)`.
2. Read params as above (`encoding.equalsIgnoreCase("base64")` -> base64 URI).
3. `Utils.checkIllegalParams(format, mode, useManifest=false, uri, precalculatedHashAlgorithm, xades=false)` throws `UnsupportedOperationException` (unchecked) when, in this order:
   - mode not `implicit`/`explicit` (case-insensitive): `"El modo de firma '<mode>' no esta soportado"`;
   - Enveloped + explicit: `"No se puede realizar una firma enveloped sobre un contenido explicito"`;
   - Externally Detached + implicit: `"No se puede realizar una firma XML Externally Detached con contenido Implicito"`;
   - Externally Detached + `uri == null` + no `precalculatedHashAlgorithm`: `"La firma XML Externally Detached necesita un Message Digest precalculado o una URI accesible"`;
   - format not one of the four XMLDSig names (case-insensitive): `"El formato de firma '<format>' no esta soportado"` (e.g. passing `XAdES Enveloped`).
4. `data == null || data.length == 0` is only allowed for `format.equals("XMLDSig Externally Detached") && uri != null`; otherwise `IllegalArgumentException("No se han indicado los datos a firmar")`.

### sign(): preparing the data element

Two random ids are generated up-front (all UUIDs are `java.util.UUID.randomUUID().toString()`, lowercase, hyphenated):
`contentId = "CONTENT-" + uuid + "-CONTENT"`, `styleId = "STYLE-" + uuid + "-STYLE"`. Flags `isBase64 = false`, `wasEncodedToBase64 = false`.

**Implicit mode.** Parse `data` with the secure DOM builder (namespace-aware, non-validating, `FEATURE_SECURE_PROCESSING`, `ACCESS_EXTERNAL_DTD/SCHEMA/STYLESHEET = ""`). Consequence: a document with an external `<!DOCTYPE … SYSTEM "x.dtd">` **fails to parse** and is therefore handled as binary (or rejected for Enveloped).

- *Parse OK (XML data)*:
  - unless `ignoreStyleSheets`, `xmlStyle = new XmlStyle(data, headless)` (see Style sheets; any exception is logged and leaves an empty style);
  - `mimeType = "text/xml"` if absent or `application/octet-stream`;
  - `encoding = doc.getXmlEncoding()` if not given (may stay `null` when the declaration has no `encoding`);
  - output properties: `ENCODING = encoding` (unless it is the base64 URI); `VERSION` and `DOCTYPE_SYSTEM` are recorded but **never used** by `Utils.writeXML` (only the encoding matters);
  - Detached: `dataElement = <CONTENT Id=contentId MimeType=mimeType Encoding=encoding>` + the document element moved inside it (attributes set with `setAttributeNS(null, …)`; a `null` encoding serialises as `Encoding=""`). If a style element was dereferenced: `<STYLE Id=styleId [MimeType=styleType] Encoding=styleEncoding>` + clone of the XSL root element.
  - other formats: `dataElement = document element` (prolog comments/PIs/DOCTYPE are dropped in every format).
- *Parse fails*:
  - Enveloped -> `InvalidXMLException` (code `510002`, "La firma requiere que los datos sean un documento XML").
  - otherwise build `<CONTENT Id=contentId …>` in a new document; `uri = null`; **`encoding` is set to the base64 URI before the following test**, so the "already Base64" test effectively ignores the user's `encoding` parameter:
    - if `Base64.isBase64(data)` (afirma-core rule: every byte in `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=_-\t\n+/0123456789\r~`, `=` only in the last two positions, count of non-CR/LF chars % 4 == 0; empty input is "Base64"): the text is inserted **as is** (`new String(data)`), `MimeType` = `MimeHelper` detection on the *decoded* bytes (fallback `application/octet-stream`), user `mimeType` discarded, **no** Base64 transform;
    - else: text = `Base64.encode(data)` (standard alphabet, padded, **no line breaks**), `MimeType` = user value, or `MimeHelper` detection when it is `application/octet-stream`/absent (fallback `application/octet-stream`; e.g. ASCII text -> `text/plain`), `wasEncodedToBase64 = true`;
    - `isBase64 = true`, attribute `Encoding="http://www.w3.org/2000/09/xmldsig#base64"`.

**Explicit mode** (never parses `data`):
- `digestValue` = SHA-1 of the bytes read from `uri` if `uri != null` (read failure -> `AOException` `411001`); else `data` itself if `precalculatedHashAlgorithm != null`; else SHA-1(`data`). The hash algorithm of explicit signatures is always SHA-1 unless precalculated.
- `dataElement = <CONTENT Id=contentId MimeType=M Encoding="http://www.w3.org/2000/09/xmldsig#base64">Base64(digestValue)</CONTENT>` with `M = "hash/" + precalculatedHashAlgorithm.toLowerCase()` or `"hash/sha1"`.
- `isBase64 = true`, `wasEncodedToBase64 = false` (so never a Base64 transform).

### sign(): container document, transforms and references

Container (`docSignature`): Enveloped -> new document whose root is the (adopted) data element; every other format -> new document with root element `<AFIRMA>` (no namespace).

Ids: `referenceId = "Reference-" + uuid`, `referenceStyleId = "StyleReference-" + uuid`, and later one shared `id = uuid` for `Signature-<id>`, `SignatureValue-<id>`, `KeyInfo-<id>`; enveloping objects `Object-<uuid>`, `StyleObject-<uuid>`.

**Base transform list** `T` (a single mutable list, shared by the data reference *and* the KeyInfo reference):
1. custom transforms from `xmlTransforms`/`xmlTransform<N>…`, in N order;
2. if `!isBase64` and C14N != `none`: the C14N transform (`canonicalizationAlgorithm`, no parameters);
3. else if `wasEncodedToBase64 && !avoidBase64Transforms`: the `#base64` transform;
4. Enveloped only (appended *after* C14N): `enveloped-signature`, then unless `avoidXpathExtraTransformsOnEnveloped` an XPath 1.0 transform with expression `not(ancestor-or-self::<prefix>:Signature)` and namespace map `{<prefix>: http://www.w3.org/2000/09/xmldsig#}`.

**References, in SignedInfo order** (all `Type="http://www.w3.org/2000/09/xmldsig#Object"` unless noted):

| Format | Data reference | Style references (see Style sheets) | Then |
|---|---|---|---|
| Enveloping | `URI="#Object-<uuid>"`, `Id=referenceId`, transforms `T` | dereferenced XSL element: `URI="#StyleObject-<uuid>"`, `Id=referenceStyleId`, transforms `[C14N]` (or none if `none`); remote `http(s)` XSL: `URI=<href>`, same Id/transforms | KeyInfo ref |
| Detached (internal) | `URI="#CONTENT-<uuid>-CONTENT"`, `Id=referenceId`, transforms `T` | dereferenced XSL: `URI="#STYLE-<uuid>-STYLE"`; remote XSL: `URI=<href>` with transform `canonicalizationAlgorithm` (created directly: fails, logged, if `none`) | KeyInfo ref |
| Externally Detached | see below | remote `http(s)` XSL only: `URI=<href>`, transforms `[C14N]` | KeyInfo ref |
| Enveloped | `URI=""`, `Id=referenceId`, transforms `T` (= `[custom…, C14N, enveloped, XPath]`) | remote XSL: `URI=<href>`, `[C14N]` | KeyInfo ref, **then** dereferenced-XSL ref `URI="#STYLE-<uuid>-STYLE"` (Object Id = `styleId`) |

Externally Detached data reference:
- `precalculatedHashAlgorithm != null` and (`uri == null` or scheme `""` or `file`): `URI=""`, `Id=referenceId`, `Type=OBJURI`, no transforms, DigestMethod mapped from the hash name (`SHA1`->`…xmldsig#sha1`, `SHA-256`->`…xmlenc#sha256`, `SHA-512`->`…xmlenc#sha512`, `RIPEMD160`->`…xmlenc#ripemd160`; others -> `AOException` `610004`), **DigestValue = `data` verbatim**.
- else `file:` URI: `URI=""`, `Id=referenceId`, `Type=OBJURI`, no transforms, DigestMethod = `referencesDigestMethod`, DigestValue = hash of the file bytes with `getDigestAlgorithmName(referencesDigestMethod)` (works for the SHA-1/256/512/RIPEMD URIs; the SHA-384 URI is not mapped -> failure).
- else (http/https/urn): `fac.newReference(uri, digestMethod)`: `URI=<uri>`, **no `Id`, no `Type`, no transforms**; dereferenced at signing time (see Digest semantics: the content is fetched, *parsed as XML* and canonicalized).
- Note: `URI=""` on an `AFIRMA` document means a standard verifier will recompute over the signature document itself, so externally-detached signatures never validate in a generic validator (confirmed). The explicit-mode `CONTENT` element built earlier is **not** inserted anywhere.

**KeyInfo reference**: `fac.newReference("#KeyInfo-<id>", digestMethod, T, null, null)` — **no `Id`, no `Type`, and the very same transform list `T`** as the data reference (including custom XPath transforms, and for Enveloped the `enveloped-signature` + XPath transforms). Because it has no `Id`, `XmlDSigUtil.cleanReferencesList` then removes any `#base64` transform from it (rebuilding it with the remaining transforms, or with no `Transforms` element at all if none remain). This cleaning also hits the id-less http externally-detached reference (it has no transforms anyway).

**KeyInfo** (`Id="KeyInfo-<id>"`): `ds:KeyValue` (RSA: `ds:RSAKeyValue/ds:Modulus,ds:Exponent`, unsigned big-endian Base64; EC: `<ECKeyValue xmlns="http://www.w3.org/2009/xmldsig11#"><NamedCurve URI="urn:oid:<curve-oid>"/><PublicKey>Base64(uncompressed point 04||X||Y)</PublicKey></ECKeyValue>` in the *default* namespace, no prefix) followed by one `ds:X509Data` with one `ds:X509Certificate` per certificate (chain order as given, or only `certChain[0]`). No `X509IssuerSerial`, no `KeyName`.

**Objects** (after KeyInfo): Enveloping: `ds:Object Id="Object-<uuid>" MimeType=mimeType Encoding=encoding` (attributes omitted when `null`), content = the data element for XML, or only its *text node* (the Base64 text) for binary/explicit; then the `StyleObject-<uuid>` object (`MimeType=styleType`, `Encoding=styleEncoding`, content = XSL root element). Enveloped with a dereferenced XSL: `ds:Object Id="STYLE-<uuid>-STYLE"` with the XSL element. Detached/Externally detached: no Object.

**SignedInfo**: `CanonicalizationMethod` = `canonicalizationAlgorithm` (inclusive C14N if `none`), `SignatureMethod` = `algoUri`. **Signature**: `Id="Signature-<id>"`, `SignatureValue Id="SignatureValue-<id>"`. Element order: `SignedInfo, SignatureValue, KeyInfo, Object*`.

**Placement**: `DOMSignContext(key, docSignature.getDocumentElement())` — the Signature is appended as **last child of the container root**: `<AFIRMA>` (after `CONTENT` for Detached) or the original root element (Enveloped). Prefix registered with `putNamespacePrefix(DSIGNNS, prefix)`; the `xmlns:<prefix>` declaration is placed on `Signature` and (redundantly) on each `XPath` element of an XPath 1.0 transform (`<ds:XPath xmlns:ds="…xmldsig#">`); XPath Filter 2.0 elements are written as `<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="subtract">…</XPath>`.

**Enveloping unwrap**: if format is Enveloping and the container holds **exactly one** element with qualified name `<prefix>:Signature` (`getElementsByTagName`, so also counts signatures inside embedded XML content), the Signature is moved to a new document and becomes the root (no `AFIRMA`). Enveloping an XML that already contains a `ds:Signature` therefore keeps the `<AFIRMA>` wrapper.

### Serialization (`Utils.writeXML`)

- DOM Level 3 `LSSerializer` with `namespaces=false`, `LSOutput.encoding = enc`, writer charset `enc`, where `enc` = output property `ENCODING` or `UTF-8`. Signature/cosign/countersign outputs therefore look like `<?xml version="1.0" encoding="UTF-8"?><root…>` — declaration immediately followed by the root, **no newline, no `standalone`, no DOCTYPE, no indentation**; prolog/epilog comments and PIs of the input are lost.
- Attribute order as serialized by Xerces: namespace declarations first, then the remaining attributes **sorted by qualified name** (e.g. `<ds:Reference Id=… Type=… URI=…>`, `<ds:Object Encoding=… Id=… MimeType=…>`, `<CONTENT Encoding=… Id=… MimeType=…>`). Empty elements are self-closed (`<ds:CanonicalizationMethod Algorithm="…"/>`). Text escaping is the standard serializer one.
- All Base64 produced by Santuario (DigestValue, SignatureValue, Modulus, X509Certificate, PublicKey) is on **one line** (`XmlDSigProviderHelper` sets `org.apache.xml.security.ignoreLineBreaks=true` and `com.sun.org.apache.xml.internal.security.lineFeedOnly=true` to avoid `&#13;`).
- Style sheet re-insertion (Enveloped only, when `xmlStyle.getStyleHref() != null`): after serialization, if the bytes are a well-formed XML document, the first `>` (end of the XML declaration) is replaced by `>\r\n<?xml-stylesheet type="<type or text/xsl>" href="<href>"?>`.

### Style sheets (`XmlStyle`, implicit XML data only)

`XmlStyle(data, headless)` searches the raw text for the first `<?xml-stylesheet ` … `>`, strips quotes, splits on spaces and loads `type=` / `href=` as properties. If both exist it tries to dereference `href`:
- `file:` scheme: always refused ("No se aceptan dereferenciaciones directas con file://"); then, if `!headless` and `href` starts with `file://`, a Swing confirm + file chooser lets the user pick the XSL; otherwise `CannotDereferenceException`.
- href whose last path segment starts with `#` (e.g. `href="#s1"`): `IsInnerlException`.
- `http(s)`: downloaded (only to read its encoding); the style *element* stays `null`, `href` kept.
- Download/parse problems: `CannotDereferenceException` / `ReferenceIsNotXmlException`.

Any exception from the constructor leaves `xmlStyle` empty (no href, no element). Practical outcomes:

| Style sheet in input | Enveloping / Detached / Ext. detached | Enveloped |
|---|---|---|
| none, or `ignoreStyleSheets=true` | nothing | nothing; an existing PI is **dropped** from the output |
| internal (`#id`), relative, `file:` (headless) | nothing | PI **dropped** |
| remote `http(s)` and downloadable | extra Reference `Id="StyleReference-<uuid>" Type=OBJURI URI=<href>` + `[C14N]` | same reference **and the PI is re-inserted textually after signing** |
| `file:` chosen via dialog (`headless=false`) | Detached: `STYLE` element + `#STYLE-…` reference; Enveloping: `StyleObject-…` Object + reference | `ds:Object Id="STYLE-…"` + reference placed after the KeyInfo reference, PI re-inserted |

**Java bug (parity decision needed)**: in the Enveloped + remote style case the PI is absent from the DOM when the `URI=""` reference is digested but present in the returned bytes, so the produced signature is **cryptographically invalid** (confirmed: removing the PI makes it validate). A faithful port reproduces this; a "fixed" port should either keep the PI in the signed DOM or not re-insert it.

### Digest semantics a Rust implementation must reproduce

The digests follow the XMLDSig 1.0 reference processing model as implemented by Santuario:
- `URI=""` -> node-set of the whole document **without comments**; `URI="#X"` -> subtree of the element whose attribute `Id` (any element; afirma registers ids by attribute name `Id`, case-insensitive in its own dereferencer) equals `X`, without comments; `URI="http(s)://…"` -> see below.
- A C14N transform turns a node-set into octets. A following transform that needs a node-set (enveloped-signature, XPath) **re-parses** those octets into a fresh document. Because of that, the `enveloped-signature` transform that follows C14N in afirma's enveloped references is a **no-op** (the "here" Signature element no longer exists in the re-parsed tree) and the actual exclusion is done by the XPath `not(ancestor-or-self::ds:Signature)`, which removes *every* `ds:Signature` subtree (so earlier/later co- and countersignatures do not break the first signature).
- `enveloped-signature` applied directly to a node-set (only when `canonicalizationAlgorithm=none`) removes the subtree of the Signature element containing the transform; applied to the `#KeyInfo-…` node-set it removes nothing (the traversal never visits the Signature element itself).
- Base64 transform: concatenated text of the node-set, Base64-decoded.
- Final node-set -> octets conversion: inclusive C14N 1.0 without comments.
- Remote `http(s)` references (style sheets and http externally-detached data): the JSR-105 default dereferencer refuses them, then `CustomUriDereferencer` downloads the URL (GET), **parses it as XML** and returns the Document as a node-set, so the digest is `H(C14N(parsed document))` (e.g. the test XSL gives `/lFR9AHSTWjyZPUP2l43kMzJnaY=` while SHA-1 of its raw bytes is `dxY0tJf+AVhjCxzyupLwRguWtGg=`). Non-XML remote content cannot be signed.

Equivalent closed forms (all confirmed numerically):
- Enveloping XML: `DigestValue = H(C14N(<ds:Object xmlns:ds="…" Encoding=… Id=… MimeType=…>content</ds:Object>))` (the inherited `xmlns:ds` is rendered on the apex element by inclusive C14N).
- Enveloping/Detached binary with `#base64`: `H(original bytes)` (e.g. SHA-1("hello world") = `Kq5sNclPz7QV2+lfQIuc6R7oRu0=`).
- Explicit / pre-encoded Base64 / `avoidBase64Transforms`: `H(C14N(Object or CONTENT element))`.
- Detached XML: `H(C14N(<CONTENT Encoding=… Id=… MimeType=…>…</CONTENT>))` (CONTENT has no namespace; nothing inherited).
- Enveloped: `H(C14N(document with all ds:Signature subtrees removed))`, e.g. `<doc><a>1</a></doc>` -> SHA-1 `qTTy37gklsHItf7qbmMqqWzqRR8=`, identical with or without the C14N/XPath transforms.
- KeyInfo reference: `H(C14N(ds:KeyInfo subtree))` in every format, where C14N is `canonicalizationAlgorithm` when that transform is in the list and inclusive C14N 1.0 otherwise (the copied enveloped/XPath transforms do not change the result; custom XPath / XPath2 transforms copied onto it *are* applied to the KeyInfo node-set and do change it).
- Countersignature: `H(C14N(ds:SignatureValue element))`, with `xmlns:ds` rendered on it.

To implement: inclusive C14N 1.0 (with/without comments), exclusive C14N 1.0, C14N 1.1 (only if those URIs are accepted), a minimal XPath 1.0 filter evaluator (at least `not(ancestor-or-self::P:Signature)`; arbitrary user expressions need a real XPath 1.0 engine), XPath Filter 2.0 (intersect/subtract/union), Base64 transform, enveloped transform, and the octets<->node-set re-parse rule above.

### Examples (real output)

**Enveloping, XML data, SHA256withECDSA, defaults — complete**:

```xml
<?xml version="1.0" encoding="UTF-8"?><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-12008f88-1b27-45e6-9177-3239d994ce1b"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference Id="Reference-baed4a96-ee25-437b-af8c-db1ea9ae2bd3" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-186805e1-c6f2-4db7-80e5-9d3041c37cf1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>7RVdV2qdgFdEC2G7Jt6VY5s6z0c=</ds:DigestValue></ds:Reference><ds:Reference URI="#KeyInfo-12008f88-1b27-45e6-9177-3239d994ce1b"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>3WwQbW+7KaEdnHYpxoMDLUSUuWA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="SignatureValue-12008f88-1b27-45e6-9177-3239d994ce1b">zl+EM++1oUzzi4PCfZecI5wYCgFv7lSJnJM65W6Cm50kgGAp3Pr4tKY8VekzwgMu9qUI8k4eMz3lTdpQBhdBqQ==</ds:SignatureValue><ds:KeyInfo Id="KeyInfo-12008f88-1b27-45e6-9177-3239d994ce1b"><ds:KeyValue><ECKeyValue xmlns="http://www.w3.org/2009/xmldsig11#"><NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><PublicKey>BL09vUGmp6N66+q367BQ/hWZ6Yu4fYoeAOfg8yo+FVH/WVSEELraAOchS23XD0tkfEb74GUZEr2ZR87Xb5Rhgl8=</PublicKey></ECKeyValue></ds:KeyValue><ds:X509Data><ds:X509Certificate>MIIBOzCB4qADAgECAgkA/vRqWW6UlM4wCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMHRUMgVGVzdDAeFw0yNjEwMTYxMTI4MjJaFw0zNjEwMTMxMTI4MjJaMBIxEDAOBgNVBAMTB0VDIFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS9Pb1Bpqejeuvqt+uwUP4VmemLuH2KHgDn4PMqPhVR/1lUhBC62gDnIUtt1w9LZHxG++BlGRK9mUfO12+UYYJfoyEwHzAdBgNVHQ4EFgQUmFWPyZxOzQKfCDARKDn5t/U+cfQwCgYIKoZIzj0EAwIDSAAwRQIgfrQdERp0zUKczWdyYL6Y02ZyqwYArjMBFtr9VEFmy/wCIQCy5pp5Hkirn5u5OP9R5S0FQTaDkzky+SWu3phSr0auPg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object Encoding="UTF-8" Id="Object-186805e1-c6f2-4db7-80e5-9d3041c37cf1" MimeType="text/xml"><doc><a>1</a></doc></ds:Object></ds:Signature>
```

Input was `<?xml version="1.0" encoding="UTF-8"?><doc><a>1</a></doc>`. Digest check vectors: SHA-1 of `<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Encoding="UTF-8" Id="Object-186805e1-c6f2-4db7-80e5-9d3041c37cf1" MimeType="text/xml"><doc><a>1</a></doc></ds:Object>` = `7RVdV2qdgFdEC2G7Jt6VY5s6z0c=`; SHA-1 of the inclusive-C14N `ds:KeyInfo` (with `xmlns:ds` on it and `<NamedCurve …></NamedCurve>` expanded) = `3WwQbW+7KaEdnHYpxoMDLUSUuWA=`.

**Enveloping, binary data (`hello world`), RSA** — note the KeyInfo reference has *no* Transforms (base64 stripped by `cleanReferencesList`):

```xml
<?xml version="1.0" encoding="UTF-8"?><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-1b68…"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference Id="Reference-2753…" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-61ee…"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>Kq5sNclPz7QV2+lfQIuc6R7oRu0=</ds:DigestValue></ds:Reference><ds:Reference URI="#KeyInfo-1b68…"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>…</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="SignatureValue-1b68…">…</ds:SignatureValue><ds:KeyInfo Id="KeyInfo-1b68…"><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>…</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue><ds:X509Data><ds:X509Certificate>…</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="Object-61ee…" MimeType="text/plain">aGVsbG8gd29ybGQ=</ds:Object></ds:Signature>
```

**Enveloping, input already "Base64-looking"** (`QUJD`): no Transforms on either reference, Object `Encoding="…#base64" MimeType="text/plain">QUJD</ds:Object>`; `getData()` returns the *decoded* `ABC`, not the original bytes.

**Enveloping, explicit** (`mode=explicit`, data `hello world`): no Transforms; `<ds:Object Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="Object-…" MimeType="hash/sha1">Kq5sNclPz7QV2+lfQIuc6R7oRu0=</ds:Object>` (Base64 of SHA-1(data)).

**Detached (internal), XML data**:

```xml
<?xml version="1.0" encoding="UTF-8"?><AFIRMA><CONTENT Encoding="UTF-8" Id="CONTENT-9ec4…-CONTENT" MimeType="text/xml"><doc><a>1</a></doc></CONTENT><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-ed80…"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference Id="Reference-9792…" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#CONTENT-9ec4…-CONTENT"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>…</ds:DigestValue></ds:Reference><ds:Reference URI="#KeyInfo-ed80…"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>…</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="SignatureValue-ed80…">…</ds:SignatureValue><ds:KeyInfo Id="KeyInfo-ed80…">…</ds:KeyInfo></ds:Signature></AFIRMA>
```

Detached binary: `<CONTENT Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="CONTENT-…-CONTENT" MimeType="text/plain">aGVsbG8gd29ybGQ=</CONTENT>`, data reference transform `#base64`, KeyInfo reference without Transforms. Detached explicit: `MimeType="hash/sha1"`, no transforms. XML without `encoding` in its declaration: `Encoding=""` on CONTENT.

**Enveloped** (input `<doc><a>1</a></doc>`):

```xml
<?xml version="1.0" encoding="UTF-8"?><doc><a>1</a><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-1dce…"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference Id="Reference-9216…" Type="http://www.w3.org/2000/09/xmldsig#Object" URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>qTTy37gklsHItf7qbmMqqWzqRR8=</ds:DigestValue></ds:Reference><ds:Reference URI="#KeyInfo-1dce…"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>…</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="SignatureValue-1dce…">…</ds:SignatureValue><ds:KeyInfo Id="KeyInfo-1dce…">…</ds:KeyInfo></ds:Signature></doc>
```

Variants: `avoidXpathExtraTransformsOnEnveloped=true` + `canonicalizationAlgorithm=none` -> both references carry only `<ds:Transform Algorithm="…#enveloped-signature"/>`; `xmlSignaturePrefix=dsig` + exclusive C14N + SHA-256 refs -> `dsig:` everywhere, XPath `not(ancestor-or-self::dsig:Signature)` declared with `xmlns:dsig`, `CanonicalizationMethod` and C14N transform `http://www.w3.org/2001/10/xml-exc-c14n#`, `DigestMethod http://www.w3.org/2001/04/xmlenc#sha256`. An ISO-8859-1 input keeps `encoding="ISO-8859-1"` and is written in that charset.

**Externally detached with precalculated hash** (`mode=explicit`, `precalculatedHashAlgorithm=SHA-256`, data = 32-byte digest):

```xml
<?xml version="1.0" encoding="UTF-8"?><AFIRMA><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-1174…"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference Id="Reference-15fe…" Type="http://www.w3.org/2000/09/xmldsig#Object" URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=</ds:DigestValue></ds:Reference><ds:Reference URI="#KeyInfo-1174…"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>…</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="SignatureValue-1174…">…</ds:SignatureValue><ds:KeyInfo Id="KeyInfo-1174…">…</ds:KeyInfo></ds:Signature></AFIRMA>
```

With `uri=file:///…`: same shape, `URI=""`, DigestMethod = referencesDigestMethod, DigestValue = hash of the file. With `uri=https://…`: `<ds:Reference URI="https://…"><ds:DigestMethod …/><ds:DigestValue>H(C14N(parsed remote XML))</ds:DigestValue></ds:Reference>` (no Id/Type/Transforms).

**Custom transforms** (`xmlTransforms=1`, `xmlTransform0Type=http://www.w3.org/2002/06/xmldsig-filter2`, `xmlTransform0Subtype=subtract`, `xmlTransform0Body=/doc/a`, Enveloping XML) — both the data and the KeyInfo reference get:

```xml
<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2"><XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="subtract">/doc/a</XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms>
```

(XPath 1.0 custom transform: `<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">not(self::a)</ds:XPath></ds:Transform>`.)

**Remote style sheet, Detached**: References `[#CONTENT-… (C14N), StyleReference-<uuid> Type=OBJURI URI="https://…/style.xslt" (C14N), #KeyInfo-… (C14N)]`.

### cosign(data, sign, algorithm, key, certChain, xParams)

`data` is ignored. Only `referencesDigestMethod`, `canonicalizationAlgorithm`, `xmlSignaturePrefix`, `includeOnlySignningCertificate` are read.

1. Algorithm URI lookup (as sign).
2. Parse `sign` (SAX error -> `AOInvalidSignatureFormatException`). If the root is `{dsig}Signature`, wrap it: new document `<AFIRMA>` + the old root as its only child.
3. Take the **first** `{dsig}Signature` in document order and **all** `{dsig}Reference` descendants of it (document order; references inside nested `Object`/`Manifest` would be included).
4. For each reference `i`: if `i == 0` or its `Id` starts with `StyleReference-`:
   - transforms = `Utils.getObjectReferenceTransforms(ref, xmlSignaturePrefix)`: finds the child element whose node name is `Transforms` or `<xmlSignaturePrefix>:Transforms` (**the prefix of the new signature, not of the existing one** — if the original used another prefix, no transforms are copied and the new signature is invalid for enveloped documents; confirmed), and rebuilds each `Transform` element child: algorithm from `@Algorithm`; XPath -> body = text of child `XPath`/`<prefix>:XPath`, namespace map `{prefix: dsig-ns}` (missing -> `InvalidAlgorithmParameterException` -> `AOException` `610005`); XPath2 -> first `XPath` child, `@Filter` must be `subtract|intersect|union`; all others without parameters (unknown algorithm -> `AOException` `213004`);
   - new Id `StyleReference-<uuid>` for style refs, else `Reference-<uuid>`;
   - if the document is "enveloping" (`isEnveloping(root)`: root local name `Signature`, or root node name `AFIRMA` whose *first child* has local name `Signature`): locate the data element via `searchDataElement(URI)` — strip one leading `#`, test the root's `Id`, then the root's children **from last to first**, and for children whose local name is `Signature`, their direct children from last to first; not found -> `AOException` `213002`. Create a new `ds:Object Id="Object-<uuid>"` containing a deep clone of **only the first child** of the found element, with `MimeType` and `Encoding` copied via `getAttribute` (absent -> `""`, serialised as `Encoding=""`). Reference `URI="#Object-<uuid>"`. Only the last created Object is kept (one variable).
   - otherwise (detached, enveloped): reference with the **same URI** as the original.
   - In all cases `Type=OBJURI` and the copied transforms.
5. New ids `Signature-<uuid>`, `SignatureValue-<uuid>`, `KeyInfo-<uuid>`. `CanonicalizationMethod = canonicalizationAlgorithm`. KeyInfo reference: `#KeyInfo-<id>`, no Id/Type, transforms `[C14N canonicalizationAlgorithm]` (always, unlike `sign`). KeyInfo content as in `sign`. Object list = the enveloping Object if any.
6. The new Signature is appended as **last child of the (possibly AFIRMA) root**. Signature failures -> `AOException` `213002` (`NoSuchAlgorithmException` -> `UnsupportedOperationException`).
7. Output via `Utils.writeXML(root, emptyProps, null, null)`: **always UTF-8** (an ISO-8859-1 input is transcoded), no style PI re-insertion.

Resulting layouts: Enveloping -> `<AFIRMA><ds:Signature …original…/><ds:Signature …new, with its own ds:Object copy of the data…/></AFIRMA>`; Detached -> `<AFIRMA><CONTENT…/><ds:Signature/><ds:Signature URI="#CONTENT-…"/></AFIRMA>`; Enveloped -> `<root>…<ds:Signature/><ds:Signature URI=""/></root>`.

### cosign(sign, algorithm, key, certChain, xParams)

Parses `sign`; clones the root into a new document and removes every `{dsig}Signature` **descendant** one by one using `rootData.removeChild(...)` (a signature that is not a direct child of the root raises `DOMException` -> `AOException` `213002`); serialises both documents with the private `writeXML(Writer, Node)` (LSSerializer `namespaces=false` into an `OutputStreamWriter` with the **platform default charset** — a latent mismatch with the declared encoding on non-UTF-8 platforms) and calls the 6-arg `cosign`. Since `data` is ignored, a port can simply call the 6-arg logic on the parsed document, but must keep the `removeChild` failure condition if exact error parity is wanted.

### countersign(sign, algorithm, targetType, targets, key, certChain, xParams)

Params read: `referencesDigestMethod`, `canonicalizationAlgorithm`, `encoding` (output charset; default = input's declared encoding; `base64` ignored -> UTF-8), `xmlSignaturePrefix`, `includeOnlySignningCertificate`. `this.algo = algorithm` (instance field).

1. Parse; record output encoding; if root is `{dsig}Signature`, wrap it in `<AFIRMA>`.
2. Select signatures (all lists are `getElementsByTagNameNS(dsig, "Signature")` over the root's descendants, document order):
   - `TREE`: snapshot of all signatures; countersign each.
   - `LEAFS`: a signature is a leaf if no `ds:Reference/@URI` anywhere in the document equals `"#" + <its first ds:SignatureValue/@Id>`. (A signature without `SignatureValue/@Id` -> `NullPointerException` -> `AOException` `213002`.)
   - `NODES`: `targets` must be non-null (`IllegalArgumentException`) and contain `Integer`s (matched with `List.contains(Integer.valueOf(i))`). Signatures are ordered in **pre-order**: for each signature in document order that has no Reference with `Type == CSURI` ("main" signature), add it and then recursively (`addSubNodes`) every signature having a Reference whose `URI == "#" + <SignatureValue Id>` of it (document order, depth-first; a self-reference stops the recursion). Index `i` of that list is countersigned when listed.
   - `SIGNERS`: signatures whose first `ds:X509Certificate` CN (`AOUtil.getCN`) is contained in `targets` (string equality).
3. For each selected signature `S`, `cs(S)`:
   - `Reference Id="Reference-<uuid>" Type="http://uri.etsi.org/01903#CountersignedSignature" URI="#" + S/ds:SignatureValue/@Id` (first SignatureValue descendant), transforms `[C14N canonicalizationAlgorithm]`, DigestMethod = referencesDigestMethod;
   - KeyInfo reference `fac.newReference("#KeyInfo-<id>", digestMethod)`: **no Transforms, no Id, no Type**;
   - `CanonicalizationMethod = canonicalizationAlgorithm`; SignatureMethod from `SIGN_ALGOS_URI.get(this.algo)`; KeyInfo as in sign; no Objects; ids `Signature-<id>`, `SignatureValue-<id>`, `KeyInfo-<id>`;
   - appended as **last child of the document element** (root, i.e. `AFIRMA` for enveloping/detached, the user root for enveloped) — countersignatures are siblings, never nested, and there is no XAdES `CounterSignature` unsigned property.
4. Output with `Utils.writeXML(root, originalProps)` (input encoding preserved, unlike cosign).

Countersignature example (TREE on an enveloping signature):

```xml
<?xml version="1.0" encoding="UTF-8"?><AFIRMA><ds:Signature … Id="Signature-ad58…">…original…</ds:Signature><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-64e1…"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference Id="Reference-c24c…" Type="http://uri.etsi.org/01903#CountersignedSignature" URI="#SignatureValue-ad58…"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>…</ds:DigestValue></ds:Reference><ds:Reference URI="#KeyInfo-64e1…"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>…</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="SignatureValue-64e1…">…</ds:SignatureValue><ds:KeyInfo Id="KeyInfo-64e1…">…</ds:KeyInfo></ds:Signature></AFIRMA>
```

### getSignersStructure(sign, asSimpleSignInfo)

1. Parse (any failure -> log + `return null`).
2. `prefix = XmlDSigUtil.guessXmlDSigNamespacePrefix(root)`: re-serialise the root and count non-overlapping occurrences of `<Signature`, `<ds:Signature`, `<dsig:Signature`, `<dsig11:Signature` (these also match `SignatureValue`, `SignatureMethod`); choose by priority `ds` (if its count is ≥ all others) > `""` > `dsig` > `dsig11`, fallback `ds`. `completePrefix = prefix == "" ? "" : prefix + ":"`.
3. If `root.getNodeName() == completePrefix + "Signature"`, wrap in `<AFIRMA>`.
4. `signatures = root.getElementsByTagName(completePrefix + "Signature")`, `signatureValues = root.getElementsByTagName(completePrefix + "SignatureValue")` — **qualified-name** matching (signatures using another prefix are invisible).
5. For each signature `i`: `ids[i] = @Id`; node user object = `asSimpleSignInfo ? Utils.getSimpleSignInfoNode("http://uri.etsi.org/01903#", sig) : CN of first ds:X509Certificate`; `refs[i]` = if the first `{dsig}Reference` has `Type == CSURI`: `Utils.getCounterSignerReferenceId` (take that reference's `URI` minus its first char, find the SignatureValue with that `Id`, return its parent's `Id`, or `""`), else `""`.
6. Tree: root `AOTreeNode("Datos")`; for each `i` (ascending) with `refs[i] == ""`: `tree.add(generaArbol(i, n-1, nodes, ids, refs)[i])`.

`generaArbol` must be ported literally (its exact recursion determines sibling order):

```text
fn genera_arbol(i, j, nodes, ids, refs):
    max = ids.len()
    if i < max && j > 0:
        if ids[i] == refs[j]: genera_arbol(i+1, j-1, …)
        if i < j:             genera_arbol(i, j-1, …)
        if ids[i] != refs[j]: return nodes
        genera_arbol(j, max-1, …)
        nodes[i].add(nodes[j])
    return nodes
```

with `AOTreeNode.add(child)` semantics: if `child` already has a parent it is first removed from it; if the parent is this same node it is re-inserted at the end (move-to-last); adding an ancestor throws `IllegalArgumentException`. For normal documents the result is: top-level signatures in document order, each countersignature under the signature it references, recursively (e.g. 2 cosigners, TREE-countersigned, then LEAFS-countersigned, then cosigned => `Datos{S1{CS1{CS1'}}, S2{CS2{CS2'}}, S3}`).

`AOSimpleSignInfo` built by `getSimpleSignInfoNode`: certs = **every** `ds:X509Certificate` in the signature subtree (whitespace stripped, Base64-decoded; undecodable -> `null` entry); signing time from `{http://uri.etsi.org/01903#}SigningTime` parsed as `yyyy-MM-dd'T'HH:mm:ss` in local time — always `null` for XMLdSig; `signAlgorithm` = the `SignatureMethod/@Algorithm` **URI**; `pkcs1` = Base64-decoded first `SignatureValue` text.

### isSign / getData / getSignInfo helpers

- `isDetached(root)`: `root.getFirstChild().getLocalName() == "CONTENT"` (a leading whitespace text node -> false; a user document whose first child element is `CONTENT` -> true).
- `isEnveloped(root)`: any `{dsig}Transform` descendant with `@Algorithm == "http://www.w3.org/2000/09/xmldsig#enveloped-signature"`.
- `isEnveloping(root)`: root local name `Signature`, or root node name `AFIRMA` and first child local name `Signature`. (Externally detached documents therefore report variant `XMLDSig Enveloping`.)

`getData(sign)`:
1. `!isSign(sign)` -> `AOInvalidSignatureFormatException("El documento no es un documento de firmas valido.")`.
2. Detached: first child `CONTENT`; if `@MimeType == "text/xml"` (exact) -> its first child (cast to Element; whitespace -> exception), else `Base64.decode(CONTENT text)` returned directly (explicit signatures return the 20-byte SHA-1).
3. Enveloped: remove signatures with a buggy loop over a **live** NodeList (`for i in 0..n: if item(i) != null: root.removeChild(item(i))`), which removes only every other direct-child signature: with 2 signatures one stays in the returned data, with 3 the middle one stays (confirmed). Non-direct-child signatures -> `DOMException` -> `AOInvalidSignatureFormatException`. Returns the root.
4. Enveloping: first `{dsig}Object` in the document; `@MimeType == "text/xml"` -> its first child element, else Base64-decode its text (also for XML signed with a custom `mimeType`, which then fails). No Object (externally detached) -> exception.
5. XML results are serialised with the private `writeXML` (LSSerializer, `namespaces=false`, platform-default charset writer) and look like `<?xml version="1.0" encoding="UTF-8"?><doc><a>1</a></doc>`; `null` if nothing matched. Any exception -> `AOInvalidSignatureFormatException("Error al leer el fichero de firmas", e)`.

### CustomUriDereferencer

`dereference(ref, ctx)`: first delegates to the JDK/Santuario default dereferencer (obtained by reflection: static field `INSTANCE` of `org.apache.jcp.xml.dsig.internal.dom.DOMURIDereferencer` or `org.jcp.xml.dsig.internal.dom.DOMURIDereferencer`). On failure:
- `http://` / `https://` URI: GET it with the installed `UrlHttpManager` (no SSL leniency), parse as XML, return it as node-set data (download/parse errors -> `URIReferenceException`);
- `URI=""`: return the whole owner document;
- otherwise strip a leading `#` and return the **first** element in document order having any attribute whose name equals `Id` case-insensitively (`id`, `ID`, `Id`) with that value; not found -> `URIReferenceException`.
Returned `Data` is `ApacheOctetStreamData` if `XMLSignatureInput.isOctetStream()`, else `ApacheNodeSetData` (Apache or Sun internal class names tried in that order).

### Errors

| Situation | Java exception (code) |
|---|---|
| Unknown signature algorithm | `AOException` `600107` |
| Illegal format/mode/uri combination | `UnsupportedOperationException` (unchecked) |
| No data (not ext.-detached with uri) | `IllegalArgumentException` |
| Enveloped with non-XML data | `InvalidXMLException` `510002` |
| Invalid `referencesDigestMethod` | `AOException` `610002` |
| Invalid `canonicalizationAlgorithm` (sign) | `AOException` `610003`; cosign/countersign: `UnsupportedOperationException` |
| Invalid precalculated hash algorithm | `AOException` `610004` |
| Explicit/ext.-detached URI cannot be read | `AOException` `411001` |
| Bad transform found while cosigning | `AOException` `213004` / `610005` |
| Any other signing failure | `AOException` `213002` (some paths `213001`) |
| `NoSuchAlgorithmException` inside JSR-105 (sign/cosign) | `UnsupportedOperationException("Hay al menos un algoritmo no soportado: …")` |
| Malformed input to cosign | `AOInvalidSignatureFormatException` |

### Differences with XAdES that are visible from this module

No `QualifyingProperties`/`SignedProperties`, no SigningTime; default reference digest SHA-1 (XAdES: SHA-512); default format Enveloping; supports `mode` (implicit/explicit) which XAdES ignores; KeyInfo is referenced *with the data transforms*; countersignatures are sibling `ds:Signature`s referencing `#SignatureValue-…` with `Type="http://uri.etsi.org/01903#CountersignedSignature"` instead of XAdES `CounterSignature` unsigned properties; cosigning an XAdES document with this signer just appends an independent XMLDSig signature.

### Java quirks to decide on (parity vs. fix)

1. Format/mode validated case-insensitively but dispatched case-sensitively (silent "sign nothing" / implicit treated as explicit).
2. The KeyInfo reference reuses the data transform list (enveloped/XPath/custom transforms applied to KeyInfo).
3. Any non-XML input that passes `Base64.isBase64` is embedded as-is and `getData` returns its decoded value.
4. Enveloped + downloadable remote `xml-stylesheet` => invalid signature (PI re-inserted after signing); all other enveloped inputs lose their style PI, prolog comments/PIs and DOCTYPE.
5. Cosign copies transforms only if the existing signature uses the same prefix as `xmlSignaturePrefix`; otherwise the new enveloped cosignature is invalid.
6. Cosign always outputs UTF-8; countersign keeps the input encoding.
7. `getData` on enveloped documents with ≥2 signatures leaves some signatures in the output.
8. Externally detached signatures use `URI=""` (local/hash cases) and never validate generically; http(s) external data is digested as canonicalized parsed XML, not raw bytes.
9. `getSignersStructure` matches signatures by qualified name with a guessed prefix.
10. External DTD declarations make the data "non-XML" (secure parser).

### Parity checklist (XMLdSig)

| Feature | Java class / method | Notes |
|---|---|---|
| Algorithm name -> SignatureMethod URI | `XMLConstants.SIGN_ALGOS_URI` | exact-string keys listed above; RSA + ECDSA only |
| Parameter validation | `Utils.checkIllegalParams(..., xades=false)` | unchecked exceptions; case-insensitive |
| Implicit XML data element | `AOXMLDSigSigner.sign` | root element only; encoding from XML decl |
| Binary -> Base64 `CONTENT` | `AOXMLDSigSigner.sign` + `Base64.isBase64/encode` + `MimeHelper` | no line wrapping; pre-encoded detection |
| Explicit mode `hash/sha1` content | `AOXMLDSigSigner.sign` | SHA-1 unless precalculated |
| Enveloping Object + unwrap of AFIRMA | `sign` | unwrap only if exactly 1 Signature |
| Detached `AFIRMA/CONTENT` | `sign` | `CONTENT-<uuid>-CONTENT` ids |
| Enveloped transforms (C14N, enveloped, XPath) | `sign` | order C14N first; prefix in XPath |
| Externally detached (hash/file/http) | `sign` | `URI=""` quirk; http parsed as XML |
| Custom transforms `xmlTransform*` | `Utils.addCustomTransforms` | XPath, XPath2, base64, enveloped |
| KeyInfo reference shares transforms | `sign` + `XmlDSigUtil.cleanReferencesList` | base64 stripped from id-less refs |
| KeyInfo content (KeyValue + X509Data) | JSR-105 `KeyInfoFactory` | EC in dsig11 default ns; `includeOnlySignningCertificate` |
| Style sheet handling | `XmlStyle`, `Utils.writeXML/addStyleSheetHeader` | `\r\n<?xml-stylesheet …?>` re-insertion |
| Id scheme | `sign`/`cosign`/`cs` | `Signature-`,`SignatureValue-`,`KeyInfo-` share one UUID; `Reference-`,`Object-`,`StyleReference-`,`StyleObject-` own UUIDs |
| Serialization | `Utils.writeXML` (LSSerializer) | no newline after decl, sorted attributes, encoding handling |
| Base64 without line breaks | `XmlDSigProviderHelper` | `ignoreLineBreaks=true` |
| Cosign | `cosign(data, sign, …)` | first signature's first ref + style refs; Object copy for enveloping; UTF-8 output |
| Cosign without data | `cosign(sign, …)` | strip signatures (direct children only) then delegate |
| Countersign TREE/LEAFS/NODES/SIGNERS | `countersign`, `countersignTree/Leafs/Nodes/Signers`, `addSubNodes`, `cs` | sibling signatures, `Type=CSURI`, pre-order for NODES |
| Signers tree | `getSignersStructure`, `generaArbol`, `AOTreeNode.add` | port recursion literally |
| Prefix guessing | `XmlDSigUtil.guessXmlDSigNamespacePrefix` | ds > "" > dsig > dsig11 |
| Simple sign info | `Utils.getSimpleSignInfoNode` | all certs; algorithm URI; old XAdES ns for SigningTime |
| isSign | `isSign` | any `{dsig}Signature` |
| getData | `getData` | live-NodeList bug; `text/xml` test |
| getSignInfo variants | `getSignInfo`, `isDetached/isEnveloped/isEnveloping` | ext.-detached reported as Enveloping |
| Fallback dereferencer | `CustomUriDereferencer` | http(s) download+parse, `Id` case-insensitive lookup |
| Signed file name | `getSignedName` | `.xsig` |
| Digest pipeline (C14N, re-parse, XPath, XPath2, base64, enveloped) | Santuario via JSR-105 | see "Digest semantics" |

---

## 7. ODF signer (`AOODFSigner`)

Java: `afirma-crypto-odf/src/main/java/es/gob/afirma/signers/odf/AOODFSigner.java` (+ `AOODFExtraParams`, `OdfXmlUtil`, `ODFErrorCode`).
Format name (`AOSignConstants.SIGN_FORMAT_ODF`): `"ODF (Open Document Format)"`.

The ODF signer produces a **plain XMLDSig** signature (no XAdES) stored in `META-INF/documentsignatures.xml`
inside the ODF ZIP package, compatible with OpenOffice.org >= 3.2 and LibreOffice (ODF 1.2 digital signatures),
optionally in the legacy OpenOffice.org 3.1 layout.

### ODF constants

| Constant | Value |
|---|---|
| Signatures file | `META-INF/documentsignatures.xml` |
| Manifest file | `META-INF/manifest.xml` |
| Root element namespace (`OPENOFFICE`) | `urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0` |
| XMLDSig namespace | `http://www.w3.org/2000/09/xmldsig#` |
| C14N algorithm (transforms + SignedInfo) | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` (inclusive, no comments) |
| Default reference digest | `http://www.w3.org/2000/09/xmldsig#sha1` |
| SignatureMethod (ALWAYS, see gotchas) | `http://www.w3.org/2000/09/xmldsig#rsa-sha1` |
| `dc` namespace | `http://purl.org/dc/elements/1.1/` |
| Supported `mimetype` contents | `application/vnd.oasis.opendocument.text`, `application/vnd.oasis.opendocument.spreadsheet`, `application/vnd.oasis.opendocument.presentation` |
| Size limit | input `>= 1_000_000_000` bytes rejected (`ErrorCode.Functional.DOCUMENT_TOO_LARGE` "501005" in sign; `IOException` in getSignersStructure) |

### ODF public API

| Method | Behaviour |
|---|---|
| `sign(data, algorithm, key, certChain, xParams)` | Adds a new signature to the ODF document `data`; returns the whole re-zipped ODF. `algorithm` is **ignored** (always RSA-SHA1). If the package already has `META-INF/documentsignatures.xml`, the new `<Signature>` is appended to it (i.e. `sign` on a signed doc == cosign). |
| `cosign(data, sign, algorithm, key, certChain, xParams)` | `return sign(sign, algorithm, key, certChain, xParams)` (`data` ignored). |
| `cosign(sign, algorithm, key, certChain, xParams)` | `return sign(sign, ...)`. |
| `countersign(...)` | Always `throw new UnsupportedOperationException("No es posible realizar contrafirmas de ficheros ODF")`. |
| `getSignersStructure(sign, asSimpleSignInfo)` / `(sign, params, asSimpleSignInfo)` | See "ODF signers tree". |
| `isSign(data)` / `isSign(data, params)` | `isValidDataFile(data)` AND a ZIP entry named exactly `META-INF/documentsignatures.xml` exists (sequential `ZipInputStream` scan). Does not parse the signatures. |
| `isValidDataFile(data)` | (1) data is ZIP (`MimeHelper.isZipData()`: JMimeMagic result `application/zip`, or first 4 bytes `50 4B 03 04` / `50 4B 05 06` / `50 4B 07 08`); (2) ZIP has an entry named `mimetype`; (3) its full content, decoded with the platform default charset, **exactly equals** one of the 3 supported MIME types (no trim; `.odg`, templates `.ott` etc. are NOT supported). Any exception -> `false`. |
| `getData(sign)` / `getData(sign, params)` | If `!isSign(sign)` -> `AOInvalidSignatureFormatException`; otherwise returns `sign` itself unchanged (the signed ODF is the data). |
| `getSignInfo(data)` / `(data, params)` | `null` -> `IllegalArgumentException`; `!isSign` -> `AOInvalidSignatureFormatException`; else `new AOSignInfo("ODF (Open Document Format)")`. |
| `getSignedName(originalName, inText)` | `inText` null -> `""`. `originalName == null` -> `inText + ".odf"`. If `originalName.length() <= 4` -> `originalName + inText + ".odf"`. If lowercase name ends with `.odt`/`.odp`/`.ods` -> base (without ext) + `inText` + same ext (lower-case ext literal). Otherwise `originalName + inText + ".odf"`. |

### ODF extraParams (complete list)

| Key | Type | Allowed values | Default | Effect |
|---|---|---|---|---|
| `referencesDigestMethod` | String (URI) | `http://www.w3.org/2000/09/xmldsig#sha1`, `http://www.w3.org/2001/04/xmlenc#sha256`, `http://www.w3.org/2001/04/xmlenc#sha512` (also `http://www.w3.org/2001/04/xmlenc#ripemd160` if a RIPEMD160 MessageDigest exists) | `http://www.w3.org/2000/09/xmldsig#sha1` | DigestMethod of ALL references (file refs, manifest ref, SignatureProperty ref). The URI is mapped to a JCA name via `AOSignConstants.getDigestAlgorithmName()`; an unmappable/unsupported URI (note: `http://www.w3.org/2001/04/xmldsig-more#sha384` does NOT map -> fails) raises `AOException` with `XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI` ("610002"). Non-URI names such as `SHA-256` also fail (`newDigestMethod` needs a URI). |
| `useOpenOffice31Mode` | boolean (`Boolean.parseBoolean`) | `true` / anything else | `false` | `true` -> legacy OOo 3.1 layout: no references to `mimetype` and `META-INF/manifest.xml`, and (when creating a new signatures file) two entries are added to the manifest (see below). OOo 3.1 signatures are incompatible with earlier and later versions, including LibreOffice. |

No other keys are read. `algorithm` (method argument) is ignored.

### ODF sign algorithm (exact)

Input: `data` (ODF ZIP), `key`, `certChain` (only `certChain[0]` is used), params.

1. Size check; parse params; `isValidDataFile(data)` else `AOFormatFileException("Los datos introducidos no se corresponden con un documento ODF", ODF_DOCUMENT_NEEDED "510003")`.
2. Open the ZIP (random access, `ZipFile` on a temp file). Read `META-INF/manifest.xml` bytes (`manifestData`) and parse it (namespace-aware, secure parser). Collect file entries with `getElementsByTagName("manifest:file-entry")` — **matching on the literal qualified name `manifest:file-entry`** (a manifest using another prefix yields zero entries).
3. Build the reference list **in this order**:
   1. (only if NOT `useOpenOffice31Mode`) `Reference URI="mimetype"`, no transforms, DigestValue = digest(raw bytes of the `mimetype` entry).
   2. (only if NOT `useOpenOffice31Mode`) `Reference URI="META-INF/manifest.xml"`, `Transforms = [C14N 1.0 inclusive]`, DigestValue = digest(C14N(document element of the ORIGINAL `manifestData`)).
   3. For each `manifest:file-entry` in document order, with `fullPath = @manifest:full-path`:
      - skip if `fullPath` ends with `/` (directories, including the root entry `/`);
      - if `fullPath` is exactly `content.xml`, `meta.xml`, `styles.xml` or `settings.xml`: `Reference URI=fullPath.replace(" ", "%20")`, `Transforms=[C14N inclusive]`, DigestValue = digest(C14N(document element of that entry));
      - else: `Reference URI=fullPath.replace(" ", "%20")`, no transforms, DigestValue = digest(raw entry bytes);
      - if `fullPath == "META-INF/documentsignatures.xml"`, the reference is NOT added (and the doc is treated as already signed).
      - A manifest entry missing from the ZIP causes an NPE -> `AOException("No ha sido posible generar la firma ODF: ...", UNKWNON_ODF_SIGNING_ERROR "213003")`.
      - Only spaces are percent-encoded in URIs; other characters are emitted verbatim. Sub-folder XML files (e.g. `Configurations2/accelerator/current.xml`, `Object 1/content.xml`) are digested as **raw bytes**, not canonicalized.
   4. `Reference URI="#<signaturePropertyId>"` (no transforms, no Type) — digest computed by the XMLDSig engine over the inclusive-C14N of the `SignatureProperty` element.
   All DigestValues for 1-3 are **precomputed** by AutoFirma (the XMLDSig engine never dereferences those relative URIs).
4. Detect cosign: `isCofirm = (manifest listed documentsignatures.xml) || (ZIP contains META-INF/documentsignatures.xml)`.
   - If `isCofirm`: parse the existing `META-INF/documentsignatures.xml` (namespace-aware) and use its document element as parent.
   - Else: create a new document with root element `document-signatures` created **without namespace** plus a literal attribute `xmlns="urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0"` (DOM `setAttribute`, not NS-aware; serialized as a normal default-namespace declaration).
     - If `useOpenOffice31Mode` (and only when creating the file): append to the manifest root two elements
       `<manifest:file-entry manifest:media-type="" manifest:full-path="META-INF/documentsignatures.xml"/>` and
       `<manifest:file-entry manifest:media-type="" manifest:full-path="META-INF/"/>` (created with non-NS `createElement`/`setAttribute`, literal qualified names).
     - In 3.2+ mode the manifest is never modified (avoids a circular reference).
5. Ids: `signatureId = UUID.randomUUID().toString()` (plain lowercase UUID, no prefix — may start with a digit), `signaturePropertyId = UUID.randomUUID().toString()`.
6. Signature property content: `<dc:date xmlns:dc="http://purl.org/dc/elements/1.1/">` + `new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss,SS").format(new Date())` + `</dc:date>`.
   - Local JVM time zone, **no offset**; comma as fraction separator; `SS` in Java prints the milliseconds with **at least 2 digits** (`5 ms -> "05"`, `123 ms -> "123"`). Example: `2026-10-16T13:17:05,123`.
7. Build the XMLDSig (JSR-105 DOM, Apache Santuario provider, base64 **without line breaks**):
   - `SignedInfo`: `CanonicalizationMethod = http://www.w3.org/TR/2001/REC-xml-c14n-20010315`, `SignatureMethod = http://www.w3.org/2000/09/xmldsig#rsa-sha1` (hard-coded), references as above.
   - `KeyInfo` (no Id): one `X509Data` with, in order, `X509SubjectName` = `cert.getSubjectX500Principal().getName()` (RFC 2253 string) and `X509Certificate` (signer cert only, base64 DER).
   - One `Object` (no Id/MimeType/Encoding) containing `SignatureProperties` (no Id) -> `SignatureProperty Id=<signaturePropertyId> Target="#<signatureId>"` -> `dc:date`.
   - `Signature Id=<signatureId>`; no Id on SignatureValue. No namespace prefix: the `Signature` element declares the default namespace `xmlns="http://www.w3.org/2000/09/xmldsig#"`.
   - Signing appends the `Signature` as the LAST child of the `document-signatures` root.
   - Signature value: PKCS#1 v1.5 RSA with SHA-1 over C14N(SignedInfo).
8. Rewrite the ZIP (see below) and return its bytes.

Smart-card errors are mapped (JMulticard `SignatureAuthException` -> `LockedKeyStoreException`/`PinException`/`AuthenticationException`; `CancelledOperationException` -> `AOCancelledSMOperationException`); a SAX error -> `AOFormatFileException(..., INTERNAL_ODF_SIGNING_ERROR "213004")`; anything else -> `AOException(UNKWNON_ODF_SIGNING_ERROR "213003")`.

### ODF canonicalization details

- File digests use XOM: the DOM document element is converted to a XOM element and canonicalized with `nu.xom.canonical.Canonicalizer(out, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")`, i.e. **inclusive C14N 1.0 without comments of the document element** (top-level PIs/comments outside the root are not part of the input; a verifier canonicalizing the whole document would include top-level PIs — edge case only).
- `SignedInfo` and the `#signaturePropertyId` reference use the Santuario inclusive C14N 1.0 (no comments). The SignatureProperty apex will render the in-scope `xmlns="http://www.w3.org/2000/09/xmldsig#"`.
- Rust port needs: inclusive C14N 1.0 (no comments) over a parsed document/element, including namespace-axis propagation for subtrees.

### ODF ZIP rewriting (exact)

`new ZipOutputStream(baos)`, then:
1. For each entry of the original ZIP in central-directory order (`ZipFile.entries()`), EXCEPT `META-INF/documentsignatures.xml` and `META-INF/manifest.xml`: `putNextEntry(new ZipEntry(name))` and write the uncompressed content.
   - Only the name is carried over: method = default **DEFLATED for every entry, including `mimetype`** (ODF requires it STORED; LibreOffice tolerates it), timestamp = current time, no extra fields/comments. Directory entries are copied as empty entries. Original order preserved, so `mimetype` stays first if it was first.
2. Append `META-INF/documentsignatures.xml`: serialization of the signatures root element.
3. Append `META-INF/manifest.xml`: serialization of the (possibly modified) manifest root element.

Serialization (`writeXML`): JAXP identity `Transformer`, `encoding=UTF-8`, no indent, source = the **root element** (not the Document), so output is `<?xml version="1.0" encoding="UTF-8"?>` immediately followed by the element (no `standalone`), without the original prolog (DOCTYPE/comments/PIs dropped). In 3.2+ mode the manifest is only re-serialized; its C14N form is unchanged, so the manifest digest stays valid. Exceptions during serialization are only logged (an empty entry could result).

### ODF signers tree (`getSignersStructure`)

1. Size check; `!isSign` -> `AOInvalidSignatureFormatException`.
2. Root node label `"Datos"`. If the signatures entry is not found -> tree with only the root.
3. Parse `documentsignatures.xml`; take all `{xmldsig}Signature` elements (`getElementsByTagNameNS`, document order, any depth).
4. For each signature: node value = `asSimpleSignInfo ? Utils.getSimpleSignInfoNode(null, signature)` (AOSimpleSignInfo with all `X509Certificate`s of the signature as chain, signing time `null`, `signAlgorithm` = first `SignatureMethod/@Algorithm`, `pkcs1` = base64-decoded first `SignatureValue`) `: CN of the first X509Certificate` (`AOUtil.getCN`).
5. Legacy countersignature nesting: if the first `Reference/@Type == "http://uri.etsi.org/01903#CountersignedSignature"`, parent id = `URI.substring(1, URI.length()-5)`; matched against parents' `Signature/@Id`, nested accordingly; others are root children. (AutoFirma ODF never produces this, so in practice all signatures are flat children of `"Datos"`.)
6. Any exception -> logged, returns a tree with a single root node `"Raíz"` (`"Raíz"`).

### ODF example (3.2+ mode, new signature, SHA-1 default)

`META-INF/documentsignatures.xml` (whitespace added for readability; real output has none between elements):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<document-signatures xmlns="urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="0e5b8c1a-6a0e-4c7e-9a43-1d1f0b4a9e21">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="mimetype">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>...</DigestValue>
      </Reference>
      <Reference URI="META-INF/manifest.xml">
        <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>...</DigestValue>
      </Reference>
      <!-- one per manifest file-entry, manifest order; e.g. -->
      <Reference URI="Configurations2/accelerator/current.xml">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</DigestValue>
      </Reference>
      <Reference URI="content.xml">
        <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>...</DigestValue>
      </Reference>
      <Reference URI="Thumbnails/thumbnail.png">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>...</DigestValue>
      </Reference>
      <!-- ... styles.xml, meta.xml, settings.xml (C14N), Pictures/x.jpg (raw) ... -->
      <Reference URI="#7c2d9f00-2b1e-4c55-8f0e-5d7a5a3b6c10">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>...</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>base64-no-linebreaks</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509SubjectName>CN=Nombre Apellido,OU=...,O=...,C=ES</X509SubjectName>
        <X509Certificate>MIIH...</X509Certificate>
      </X509Data>
    </KeyInfo>
    <Object>
      <SignatureProperties>
        <SignatureProperty Id="7c2d9f00-2b1e-4c55-8f0e-5d7a5a3b6c10" Target="#0e5b8c1a-6a0e-4c7e-9a43-1d1f0b4a9e21">
          <dc:date xmlns:dc="http://purl.org/dc/elements/1.1/">2026-10-16T13:17:05,123</dc:date>
        </SignatureProperty>
      </SignatureProperties>
    </Object>
  </Signature>
</document-signatures>
```

(`2jmj7l5rSw0yVb/vlWAYkK/YBwk=` = SHA-1 of the empty byte string, as for the 0-byte `current.xml` of the test ODFs.)
In `useOpenOffice31Mode=true` the `mimetype` and `META-INF/manifest.xml` references are absent and the manifest gains the two `file-entry` elements shown above. On cosign, a second `<Signature>` is appended to the same root with fresh UUIDs; the existing ones are untouched (whitespace/prolog of the old file are re-serialized).

### ODF real output (verified)

Real `META-INF/documentsignatures.xml` produced by the current code (JDK 21) for the test document `afirma-crypto-odf/src/test/resources/odt` with the EIDAS test certificate and algorithm `SHA256withRSA` (ignored: the SignatureMethod is still rsa-sha1). Indentation added, long Base64 truncated. Note the RFC 2253 `X509SubjectName` with hex-encoded values for attribute types without an RFC 2253 keyword (`2.5.4.4=#0c11...`). Output ZIP (`unzip -lv`): every entry `Defl:N` (also `mimetype` and directory entries), `META-INF/documentsignatures.xml` and `META-INF/manifest.xml` last. A cosign appends a second `<Signature>` with fresh UUIDs to the same root.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<document-signatures xmlns="urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="8f6ac1b6-6341-4436-8c7b-4112e1868d41">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="mimetype">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>kBA8vElORIEynUWPvr1bzZKG3hw=</DigestValue>
      </Reference>
      <Reference URI="META-INF/manifest.xml">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>DrD7P5Bwg6kZh/aq7GxZdtvV/mQ=</DigestValue>
      </Reference>
      <Reference URI="Configurations2/accelerator/current.xml">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</DigestValue>
      </Reference>
      <Reference URI="Pictures/100000000000028000000115561F6D35.jpg">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>L07GDCbl0N1fLt2LkRhDfXx+ZWs=</DigestValue>
      </Reference>
      <Reference URI="content.xml">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>E0dqzCVP7rPIiREUHd/1XOsSsmc=</DigestValue>
      </Reference>
      <Reference URI="styles.xml">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>x2ZABUei3AZPpFvMtNF7Ud/Uzzk=</DigestValue>
      </Reference>
      <Reference URI="meta.xml">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>oobBcDEILF/I8/FdqbKb5dyAmF4=</DigestValue>
      </Reference>
      <Reference URI="Thumbnails/thumbnail.png">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>FACzct2jZ8++ECi+t/k11wJOTLs=</DigestValue>
      </Reference>
      <Reference URI="settings.xml">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>O4adLHu0il4MB2N1HLbXVJlViPg=</DigestValue>
      </Reference>
      <Reference URI="#627d5bc9-b125-4bc4-8ba4-352620ba1372">
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>byznH66amkSZdpPQq/TMh9vyHaI=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>tS/UqVxifz…</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509SubjectName>CN=EIDAS CERTIFICADO PRUEBAS - 99999999R,2.5.4.4=#0c11454944415320434552544946494341444f,2.5.4.42=#0c0750525545424153,2.5.4.5=#130f49444345532d393939393939393952,C=ES</X509SubjectName>
        <X509Certificate>MIIHhjCCBm…</X509Certificate>
      </X509Data>
    </KeyInfo>
    <Object>
      <SignatureProperties>
        <SignatureProperty Id="627d5bc9-b125-4bc4-8ba4-352620ba1372" Target="#8f6ac1b6-6341-4436-8c7b-4112e1868d41">
          <dc:date xmlns:dc="http://purl.org/dc/elements/1.1/">2026-10-16T13:51:38,285</dc:date>
        </SignatureProperty>
      </SignatureProperties>
    </Object>
  </Signature>
</document-signatures>
```

### ODF gotchas

- `algorithm` is ignored: SignatureMethod is always `rsa-sha1` (an EC key would fail at signing). Reference digests are configurable only through `referencesDigestMethod`.
- Only `content.xml`, `meta.xml`, `styles.xml`, `settings.xml` at the package root are canonicalized; all other entries (including other XML) are hashed raw.
- Only files listed in `manifest.xml` are referenced (non-listed ZIP entries are unsigned). `mimetype`/manifest refs are always first.
- The output re-compresses `mimetype` (DEFLATED) and resets all ZIP timestamps; `documentsignatures.xml` and `manifest.xml` are moved to the end of the archive.
- `dc:date` has no time-zone and a 2-or-3 digit millisecond field after a comma.
- The `manifest:file-entry` lookup is by literal qualified name (prefix must be `manifest`).
- Signature ids are bare UUIDs (not valid NCName if they start with a digit; Santuario does not care).

---

## 8. OOXML signer (`AOOOXMLSigner`)

Java: `afirma-crypto-ooxml/src/main/java/es/gob/afirma/signers/ooxml/` — `AOOOXMLSigner` (API), `OOXMLXAdESSigner` (builds the signature XML), `OOXMLAdvancedSignature` (extends jxades `XMLAdvancedSignature`, does the JSR-105 signing), `OOXMLPackageObjectHelper` (`idPackageObject`), `OOXMLOfficeObjectHelper` (`idOfficeObject`), `OOXMLZipHelper` (package rewriting), `ContentTypeManager`, `OOXMLURIDereferencer`, `RelationshipsParser`/`Relationship`, `OOXMLUtil`, `relprovider/RelationshipTransformService` (+ `OOXMLProvider`, `RelationshipTransformParameterSpec`, `RelationshipComparator`). Depends on `afirma-crypto-xades` (`XAdESUtil.parseCommitmentTypeIndications`, `AOXAdESSigner` for the signers tree) and jxades `es.uji.crypto.xades:jxades:0.2.2`.
Format name (`AOSignConstants.SIGN_FORMAT_OOXML`): `"OOXML (Office Open XML)"`.

The output is an OPC (ECMA-376 Part 2) package signature: a XAdES-EPES (implied policy, XAdES 1.3.2 namespace) **enveloping** XMLDSig stored as `_xmlsignatures/sig-<UUID>.xml`, with Office-specific objects `idPackageObject` and `idOfficeObject`.

### OOXML constants

| Item | Value |
|---|---|
| XAdES namespace | `http://uri.etsi.org/01903/v1.3.2#` (prefix `xd`) |
| XMLDSig prefix | `ds` (`http://www.w3.org/2000/09/xmldsig#`) |
| SignedProperties Type | `http://uri.etsi.org/01903#SignedProperties` |
| Object reference Type | `http://www.w3.org/2000/09/xmldsig#Object` |
| SignedInfo C14N | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` |
| SignedInfo reference digests + XAdES CertDigest | SHA-512 `http://www.w3.org/2001/04/xmlenc#sha512` (hard-coded) |
| Manifest (package part) reference digests | SHA-256 `http://www.w3.org/2001/04/xmlenc#sha256` (hard-coded) |
| RelationshipTransform URI | `http://schemas.openxmlformats.org/package/2006/RelationshipTransform` |
| OPC digital-signature ns (`mdssi`) | `http://schemas.openxmlformats.org/package/2006/digital-signature` |
| MS digsig ns | `http://schemas.microsoft.com/office/2006/digsig` |
| Relationships ns | `http://schemas.openxmlformats.org/package/2006/relationships` |
| Content-types ns | `http://schemas.openxmlformats.org/package/2006/content-types` |
| Relationship part content type | `application/vnd.openxmlformats-package.relationships+xml` |
| Signature part content type | `application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml` |
| Origin part content type (Default ext `sigs`) | `application/vnd.openxmlformats-package.digital-signature-origin` |
| Origin rel type | `http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin` |
| Signature rel type | `http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature` |
| Size limit | `>= 1_000_000_000` bytes -> `IOException("El archivo tiene un tamano superior al permitido.")` |

Signature algorithm: `XMLConstants.SIGN_ALGOS_URI.get(algorithm)`; keys `SHA1withRSA`/`RSA`/`SHA-1withRSA`/... -> `http://www.w3.org/2000/09/xmldsig#rsa-sha1`; `SHA256withRSA` -> `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`; `SHA384withRSA` -> `...#rsa-sha384`; `SHA512withRSA` -> `...#rsa-sha512`; `SHA1withECDSA`/`ECDSA` -> `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1`; `SHA224withECDSA`, `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA` -> `...#ecdsa-shaNNN` (plus the `SHA-NNN...` / `...Encryption` aliases). Unknown -> `IllegalArgumentException("Los formatos de firma XML no soportan el algoritmo de firma '<alg>'")`, wrapped by `signOOXML` into `AOException(UNKWNON_OOXML_SIGNING_ERROR "213005")`.

### OOXML public API

| Method | Behaviour |
|---|---|
| constructor | Throws `UnsupportedJreVersionException` on Java 1.6; registers JCA provider `OOXMLProvider` exposing `TransformService.<RelationshipTransform URI>` (MechanismType `DOM`). |
| `sign(data, algorithm, key, certChain, extraParams)` | size check; `OfficeAnalizer.isOOXMLDocument(data)` (ZipFile has entries `[Content_Types].xml`, `_rels/.rels`, `docProps/app.xml`, `docProps/core.xml`) else `AOFormatFileException(..., OOXML_DOCUMENT_NEEDED "510004")`; empty chain -> `IllegalArgumentException`; `key == null` -> `IllegalArgumentException`. Then **only `certChain[0]` is used** ("Office 2016 no acepta cadenas"), signature XML built by `OOXMLXAdESSigner.getSignedXML`, package rewritten by `OOXMLZipHelper.outputSignedOfficeOpenXMLDocument`. Returns the whole new package. Works the same on an already signed document (adds a signature). |
| `cosign(sign, algorithm, key, certChain, extraParams)` | `return sign(sign, ...)`. |
| `cosign(data, sign, ...)` | `return cosign(sign, ...)` (`data` ignored). |
| `countersign(...)` | `throw new UnsupportedOperationException("No es posible realizar contrafirmas de ficheros OOXML")`. |
| `isValidDataFile(data)` | `null` -> false; ZIP magic (`MimeHelper.isZipData`) AND entries `[Content_Types].xml`, (`_rels/.rels` or `_rels\.rels`), (`docProps/app.xml` or `docProps\app.xml`), (`docProps/core.xml` or `docProps\core.xml`). |
| `isSign(sign)` / `(sign, params)` | `null` -> false; `isValidDataFile && countOOXMLSignatures(sign) > 0`; any exception -> false. |
| `getData(sign)` | `!isSign` -> `AOInvalidSignatureFormatException`; else returns `sign` unchanged. |
| `getSignInfo(data)` | `null` -> `IllegalArgumentException`; `!isSign` -> `AOFormatFileException(OOXML_DOCUMENT_NEEDED)`; else `new AOSignInfo("OOXML (Office Open XML)")`. |
| `getSignersStructure(sign, [params,] asSimpleSignInfo)` | `null` -> `IllegalArgumentException`; size check (`IOException`); `!isSign` -> returns `null`. Root `"Datos"`; for each signature XML from `OOXMLUtil.getOOXMLSignatures(sign)` (order of signature relationships in the origin rels part): run `new AOXAdESSigner().getSignersStructure(sigXml, asSimpleSignInfo)` and add `root.getChildAt(0)` of that tree. Any exception -> `null`. |
| `getSignedName(originalName, inText)` | `inText` null -> `""`; `originalName == null` -> `inText + ".ooxml"`; ends (case-insensitive) with `.docx`/`.xlsx`/`.pptx`/`.ppsx` -> base + inText + that ext; else `originalName + inText + ".ooxml"`. |

### OOXML extraParams (complete list actually read by code)

| Key | Type | Default | Effect |
|---|---|---|---|
| `signatureProductionCity` | String | absent | `xd:SignatureProductionPlace/xd:City`. |
| `signatureProductionProvince` | String | absent | `xd:SignatureProductionPlace/xd:StateOrProvince`. |
| `signatureProductionPostalCode` | String | absent | `xd:SignatureProductionPlace/xd:PostalCode`. |
| `signatureProductionCountry` | String | absent | `xd:SignatureProductionPlace/xd:CountryName`. `SignatureProductionPlace` is emitted iff at least one of the 4 is non-null; each child only if non-null (order City, StateOrProvince, PostalCode, CountryName). Empty strings are emitted as empty elements. |
| `signerClaimedRoles` | String | absent | If present: `xd:SignerRole/xd:ClaimedRoles/xd:ClaimedRole` with the **whole value as ONE role** (no `\|` splitting, unlike the XAdES signer). |
| `signatureComments` | String | absent | `SignatureInfoV1/SignatureComments` in `idOfficeObject` (shown by Office as "purpose for signing"). |
| `signatureAddress1` | String | absent | `SignatureInfoV2/Address1`. |
| `signatureAddress2` | String | absent | `SignatureInfoV2/Address2`. |
| `commitmentTypeIndications` | int as String (>= 1) | absent | Number of CommitmentTypeIndications; parsed by `XAdESUtil.parseCommitmentTypeIndications(xParams, null)` (shared with XAdES). Non-integer or < 1 -> logged, none added. NOTE the parser loop is `for (i = 0; i <= n; i++)`, so indices `0..n` inclusive are scanned and missing ones skipped. |
| `commitmentTypeIndication<i>Identifier` | `"1".."6"` | — (required per CTI) | 1 `http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin`, 2 `...#ProofOfReceipt`, 3 `...#ProofOfDelivery`, 4 `...#ProofOfSender`, 5 `...#ProofOfApproval`, 6 `...#ProofOfCreation`. Other values -> that CTI skipped. |
| `commitmentTypeIndication<i>Description` | String | absent | `xd:CommitmentTypeId/xd:Description` (empty element when absent). |
| `commitmentTypeIndication<i>DocumentationReferences` | `\|`-separated URLs | absent | Each must parse as `java.net.URL` (else skipped) -> `xd:DocumentationReferences/xd:DocumentationReference`. |
| `commitmentTypeIndication<i>CommitmentTypeQualifiers` | `\|`-separated strings | absent | `xd:CommitmentTypeQualifiers/xd:CommitmentTypeQualifier` each. |

Side effect: if at least one CTI was parsed, `SignatureInfoV1/SignatureType` = `"1"`.

Documented in `doc-files/extraparams.html` / used by tests but **ignored by the code**: `includeOnlySignningCertificate` (behaviour is always "signer cert only"), `signerClaimedRole` (singular — real key is `signerClaimedRoles`), `signatureReason`, `format`. No policy, no timestamp, no `xadesNamespace`, no digest configuration is supported in OOXML.

### OOXML signature XML — overall structure

Ids (with `P = "xmldsig-" + UUID.randomUUID()`):

| Element | Id |
|---|---|
| `ds:Signature` | `P-Signature` |
| `ds:SignatureValue` | `P-SignatureValue` |
| `ds:KeyInfo` | `P-KeyInfo` |
| `ds:Object` #1 | `idPackageObject` (fixed) |
| `ds:Object` #2 | `idOfficeObject` (fixed) |
| `ds:Object` #3 (XAdES) | none |
| `xd:QualifyingProperties` | `P-QualifyingProperties`, `Target="#P-Signature"` |
| `xd:SignedProperties` | `P-SignedProperties` |
| `ds:SignatureProperty` (time) | `idSignatureTime`, `Target="#P"` (**not** `#P-Signature` — mismatch kept from Java) |
| `ds:SignatureProperties` (time) | `id-signature-time-<UUID>` |
| `ds:SignatureProperty` (office) | `idOfficeV1Details`, `Target="#P"` (same mismatch) |

Document: a fresh DOM document whose root becomes `ds:Signature` (`xmlns:ds` declared on it).

`ds:SignedInfo`:
- `CanonicalizationMethod` `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
- `SignatureMethod` from `SIGN_ALGOS_URI`
- References, in this exact order:
  1. `URI="#idPackageObject"` `Type="http://www.w3.org/2000/09/xmldsig#Object"`, no transforms, SHA-512.
  2. `URI="#idOfficeObject"` `Type="http://www.w3.org/2000/09/xmldsig#Object"`, no transforms, SHA-512.
  3. `URI="#P-SignedProperties"` `Type="http://uri.etsi.org/01903#SignedProperties"`, `Transforms=[http://www.w3.org/TR/2001/REC-xml-c14n-20010315]`, SHA-512.
  4. `URI="#P-KeyInfo"`, no Type, no transforms, SHA-512.
  No reference has an Id. Same-document references without transforms are digested over inclusive C14N 1.0 (no comments) of the referenced element (XMLDSig default for node-sets).

Engine digest order (JSR-105 `DOMXMLSignature.sign`): first all references of every `ds:Manifest` inside the Objects, then SignedInfo references — so `#idPackageObject` covers the already-filled Manifest DigestValues.

`ds:SignatureValue`: raw signature (RSA PKCS#1 v1.5 / ECDSA as XMLDSig r||s) base64 without line breaks.

`ds:KeyInfo Id="P-KeyInfo"` (`OOXMLAdvancedSignature.newKeyInfo` override): `ds:KeyValue` (from `certChain[0].getPublicKey()`: `ds:RSAKeyValue/ds:Modulus,ds:Exponent` for RSA; `dsig11:ECKeyValue` for EC as produced by Santuario) followed by `ds:X509Data/ds:X509Certificate` (signer cert only). No X509SubjectName / IssuerSerial.

`ds:Object` order in the Signature: `idPackageObject`, `idOfficeObject`, XAdES object.

### `idPackageObject` (OOXMLPackageObjectHelper)

```
<ds:Object Id="idPackageObject">
  <ds:Manifest> refs... </ds:Manifest>
  <ds:SignatureProperties Id="id-signature-time-<UUID>">
    <ds:SignatureProperty Id="idSignatureTime" Target="#P">
      <mdssi:SignatureTime xmlns:mdssi="http://schemas.openxmlformats.org/package/2006/digital-signature">
        <mdssi:Format>YYYY-MM-DDThh:mm:ssTZD</mdssi:Format>
        <mdssi:Value>VALUE</mdssi:Value>
      </mdssi:SignatureTime>
    </ds:SignatureProperty>
  </ds:SignatureProperties>
</ds:Object>
```

`VALUE` = `new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss'Z'").format(new Date())` — **local time, 12-hour clock (`hh` = 01..12, no AM/PM), followed by a literal `Z`** (not UTC). Replicate exactly for parity (e.g. 13:17:05 local -> `2026-10-16T01:17:05Z`).

Manifest construction (`constructManifest`), all references with DigestMethod SHA-256:

A. **Relationship parts** (`addRelationshipsReferences`): iterate ZIP entries sequentially (local-header order, `ZipInputStream`); for every entry whose name ends with `.rels` (anywhere, including `_rels/.rels`, `word/_rels/document.xml.rels`, `customXml/_rels/...`, and on cosign `_xmlsignatures/_rels/origin.sigs.rels`):
   - parse it (namespace-aware); for each **element** child of the root in document order read `@Type`; skip if Type is one of:
     - `http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties`
     - `http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties`
     - `http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin`
     - `http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail`
     - `http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps`
     - `http://schemas.openxmlformats.org/officeDocument/2006/relationships/viewProps`
   - collect `@Id` of the others (document order, duplicates kept) as SourceIds;
   - reference: `URI="/" + entryName + "?ContentType=application/vnd.openxmlformats-package.relationships+xml"`, Transforms = `[RelationshipTransform(SourceIds), C14N 1.0 inclusive]`. Added even if the SourceId list is empty. No de-duplication at this step.
B. **Content parts** (`addParts`): parse `[Content_Types].xml` into a `ContentTypeManager`; iterate ZIP entries sequentially; keep entries whose name `startsWith` any of `"word"`, `"excel"`, `"xl"`, `"powerpoint"` (plain string prefix, so `wordfoo/x` matches; **`ppt/` does NOT match — PowerPoint parts are not signed, only their .rels**; `docProps/`, `customXml/` etc. are never signed); compute content type; if non-null add `URI="/" + entryName + "?ContentType=" + contentType` with no transforms, unless a reference with the identical URI already exists (this drops the `word/_rels/*.rels` duplicates from step A).
   - Content type resolution: `partName = "/" + entryName` (if not already starting with `/`); `Override[@PartName]` exact, case-sensitive match first; else extension after the last `.` (none or trailing dot -> null) looked up case-sensitively in `Default[@Extension]`; else null (entry skipped — e.g. directory entries `word/`). `[Content_Types].xml` children are matched by node name `Default`/`Override` (no prefix expected); elements missing an attribute are skipped with a warning.
   - URIs are not percent-encoded (part names emitted verbatim).

The Manifest references are dereferenced by `OOXMLURIDereferencer`: `URLDecoder.decode(uri, UTF-8)` (so `+` becomes a space and `%xx` sequences are decoded), strip a leading `/`, strip everything from the first `?`, find the ZIP entry with exactly that name (sequential scan of the ORIGINAL input package) and return its **uncompressed bytes as an octet stream**; if not found, fall back to the default JSR-105 dereferencer (used for `#id` same-document refs).

### `idOfficeObject` (OOXMLOfficeObjectHelper)

```
<ds:Object Id="idOfficeObject">
  <ds:SignatureProperties>
    <ds:SignatureProperty Id="idOfficeV1Details" Target="#P">
      <SignatureInfoV1 xmlns="http://schemas.microsoft.com/office/2006/digsig">
        <SetupID/>
        <SignatureText/>
        <SignatureImage/>
        [<SignatureComments>{signatureComments}</SignatureComments>]      (iff param present)
        [<WindowsVersion>{System.getProperty("os.version")}</WindowsVersion>]  (iff running on Windows)
        <OfficeVersion>16.0</OfficeVersion>
        <ApplicationVersion>16.0</ApplicationVersion>
        <Monitors>{number of AWT screen devices}</Monitors>
        <HorizontalResolutionElement>{screen width px}</HorizontalResolutionElement>
        <VerticalResolutionElement>{screen height px}</VerticalResolutionElement>
        <ColorDepth>{bit depth of screen device 0}</ColorDepth>
        <SignatureProviderId>{00000000-0000-0000-0000-000000000000}</SignatureProviderId>
        <SignatureProviderUrl/>
        <SignatureProviderDetails>9</SignatureProviderDetails>
        [<SignatureType>1</SignatureType>]     (iff >= 1 CommitmentTypeIndication parsed)
      </SignatureInfoV1>
      <SignatureInfoV2 xmlns="http://schemas.microsoft.com/office/2006/digsig">
        [<Address1>{signatureAddress1}</Address1>]
        [<Address2>{signatureAddress2}</Address2>]
      </SignatureInfoV2>
    </ds:SignatureProperty>
  </ds:SignatureProperties>
</ds:Object>
```

Notes: element names `HorizontalResolutionElement`/`VerticalResolutionElement` are wrong w.r.t. the MS schema (`HorizontalResolution`/`VerticalResolution`) but are what Java emits — keep them for parity. Monitors/resolution/ColorDepth come from AWT (`GraphicsEnvironment`, `Toolkit.getScreenSize()`); in a headless JVM this throws (signing fails). A Rust port must supply values (e.g. real display info, or `1`, `1920`, `1080`, `32`) — document the choice. `SignatureInfoV2` is always present (possibly empty). The `ds:SignatureProperties` here has no Id.

### XAdES object (jxades 0.2.2 via `OOXMLAdvancedSignature`)

Instance: `XAdES.newInstance(XAdES.EPES, "http://uri.etsi.org/01903/v1.3.2#", "xd", "ds", DigestMethod.SHA512, doc, null)`; `setSigningCertificate(cert)`, optional `setSignatureProductionPlace`, `setCommitmentTypeIndications`, `setSignerRole`, `setSigningTime(new Date())` (value ignored, see below); `OOXMLAdvancedSignature.newInstance` sets `SignaturePolicyIdentifierImpl(implied=true)`.

Structure (children emitted in jxades `XAdES.Element` enum order: SigningTime, SigningCertificate, SignaturePolicyIdentifier, SignatureProductionPlace, SignerRole; then SignedDataObjectProperties only if CTIs exist; no UnsignedProperties):

```
<ds:Object>
  <xd:QualifyingProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xd="http://uri.etsi.org/01903/v1.3.2#"
                           Id="P-QualifyingProperties" Target="#P-Signature">
    <xd:SignedProperties Id="P-SignedProperties">
      <xd:SignedSignatureProperties>
        <xd:SigningTime>2026-10-16T13:17:05+02:00</xd:SigningTime>
        <xd:SigningCertificate>
          <xd:Cert>
            <xd:CertDigest>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
              <ds:DigestValue>{base64(SHA-512(cert DER))}</ds:DigestValue>
            </xd:CertDigest>
            <xd:IssuerSerial>
              <ds:X509IssuerName>{cert.getIssuerDN().getName()}</ds:X509IssuerName>
              <ds:X509SerialNumber>{decimal serial}</ds:X509SerialNumber>
            </xd:IssuerSerial>
          </xd:Cert>
        </xd:SigningCertificate>
        <xd:SignaturePolicyIdentifier><xd:SignaturePolicyImplied/></xd:SignaturePolicyIdentifier>
        [<xd:SignatureProductionPlace>[<xd:City/>][<xd:StateOrProvince/>][<xd:PostalCode/>][<xd:CountryName/>]</xd:SignatureProductionPlace>]
        [<xd:SignerRole><xd:ClaimedRoles><xd:ClaimedRole>{signerClaimedRoles}</xd:ClaimedRole></xd:ClaimedRoles></xd:SignerRole>]
      </xd:SignedSignatureProperties>
      [<xd:SignedDataObjectProperties>
        <xd:CommitmentTypeIndication>                       (one per parsed CTI, in index order)
          <xd:CommitmentTypeId>
            <xd:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin</xd:Identifier>
            <xd:Description>{description or empty}</xd:Description>
            [<xd:DocumentationReferences><xd:DocumentationReference>{url}</xd:DocumentationReference>...</xd:DocumentationReferences>]
          </xd:CommitmentTypeId>
          <xd:AllSignedDataObjects/>
          <xd:CommitmentTypeQualifiers>[<xd:CommitmentTypeQualifier>{q}</xd:CommitmentTypeQualifier>...]</xd:CommitmentTypeQualifiers>
        </xd:CommitmentTypeIndication>
      </xd:SignedDataObjectProperties>]
    </xd:SignedProperties>
  </xd:QualifyingProperties>
</ds:Object>
```

Exact details:
- `SigningTime` is generated at marshalling with `new Date()` (jxades `SignedSignatureProperties.setSigningTime()` ignores the stored value), formatted `yyyy-MM-dd'T'HH:mm:ssZ` with a `:` inserted before the last two chars -> `2026-10-16T13:17:05+02:00` (local zone, no millis).
- `CertDigest/DigestValue`: base64 (jxades `Base64.encodeBytes`, no line breaks) of SHA-512 over the DER certificate. The `ds:DigestMethod/@Algorithm` attribute is created by jxades with `setAttributeNS("ds", "Algorithm", ...)` (namespace URI literally `"ds"`, no prefix); it serializes and canonicalizes as a plain `Algorithm="..."` attribute — emit a plain attribute.
- `X509IssuerName` = Java `X509Certificate.getIssuerDN().getName()` (sun `X500Name.toString()`: RDNs most-significant-last order like RFC 2253 but separated by `", "`, keywords `CN, OU, O, L, ST, C, STREET, DC, UID, EMAILADDRESS, SERIALNUMBER, SURNAME, GIVENNAME, T, ...`, unknown OIDs as `OID.x.y.z=value`). This differs from the RFC 2253 string; a Rust port must reproduce the Java legacy formatting for parity.
- `CommitmentTypeId/Identifier` gets a `Qualifier="OIDAsURN"` attribute only when the identifier starts with `urn:oid:` — never with the 6 supported URIs.
- `ObjectReference` is never used in OOXML (`AllSignedDataObjects` always).
- No `DataObjectFormat`, no `SignerRoleV2`, no `SigningCertificateV2`, no unsigned properties, no timestamps.

### RelationshipTransform (must be implemented)

Marshalled form inside each relationship Manifest reference (the transform's `marshalParams` adds `xmlns:mdssi` on the `ds:Transform` element and one child per SourceId, in collection order):

```xml
<ds:Transform Algorithm="http://schemas.openxmlformats.org/package/2006/RelationshipTransform"
              xmlns:mdssi="http://schemas.openxmlformats.org/package/2006/digital-signature">
  <mdssi:RelationshipReference SourceId="rId1"/>
  <mdssi:RelationshipReference SourceId="rId3"/>
</ds:Transform>
<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
```

Parsing (validation path, `init(XMLStructure parent, ...)`): SourceIds = XPath `mdssi:RelationshipReference/@SourceId` relative to the `ds:Transform` element. **`mdssi:RelationshipsGroupReference/@SourceType` is NOT supported** (signatures from Office that use SourceType selectors cannot be verified by this implementation; for verification parity a Rust port may add it, ECMA-376-2 §13.2.4.24).

Transform processing (`transform(Data)`), input = octet stream of the `.rels` part:
1. Parse the bytes as XML (namespace-aware, secure; no DTD).
2. Iterate the root (`Relationships`) children in order:
   - remove every non-element child (whitespace text, comments, PIs);
   - remove every element whose `@Id` is not in the SourceId list (exact string comparison);
   - for every element (including removed ones — harmless) lacking a `TargetMode` attribute, add `TargetMode="Internal"` (no namespace).
3. Sort the remaining `Relationship` elements by `@Id` using Java `String.compareTo` (UTF-16 code-unit lexicographic; for ASCII ids = byte order, so `rId10 < rId2`), and re-append them in that order.
4. Serialize the document with the JAXP identity transformer, `omit-xml-declaration=yes`, and return it as an octet stream.
5. The next transform (inclusive C14N 1.0) re-parses that octet stream and canonicalizes the whole document, which yields e.g.:

```
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="word/document.xml" TargetMode="Internal" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"></Relationship></Relationships>
```

(C14N: attributes sorted by name — `Id`, `Target`, `TargetMode`, `Type` — empty elements expanded to start/end tags, no XML declaration.) The digest is SHA-256 over those bytes. Element content of `Relationship` (none in practice) would be kept. A Rust implementation can directly produce the canonical string: filter, add TargetMode, sort by Id, then C14N.

### OOXML signature XML serialization

`writeXML`: DOM Level 3 `LSSerializer` of the Signature document element with `namespaces=false` (no namespace fix-up; all needed `xmlns` attributes were added explicitly), UTF-8 output, default config (XML declaration `<?xml version="1.0" encoding="UTF-8"?>`, no pretty printing). The bytes are re-parsed only as a sanity check. Since everything is signed via C14N of DOM nodes, exact serialization whitespace does not affect validity as long as no whitespace is added inside signed subtrees.

### OOXML package rewriting (OOXMLZipHelper)

`signatureZipEntryName = "_xmlsignatures/sig-" + UUID + ".xml"` (Office uses `sig1.xml`; AutoFirma uses a random UUID name). The signature is computed over the ORIGINAL package first; then the package is rewritten:

For each entry of the original ZIP, in sequential (local header) order, `putNextEntry(new ZipEntry(name))` (DEFLATED, current timestamp, no extra fields) and:
- `[Content_Types].xml`: parse; append `<Override PartName="/_xmlsignatures/sig-<UUID>.xml" ContentType="application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"/>` (element in the content-types namespace, no prefix) as last child of `Types`; if XPath `/tns:Types/tns:Default[@Extension='sigs']` matches nothing, also append `<Default Extension="sigs" ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/>` (after the Override). Serialize (identity transformer, XML declaration kept; `standalone` is dropped when the source said `yes`, `standalone="no"` otherwise).
- `_rels/.rels`: if XPath `/tns:Relationships/tns:Relationship[@Type='http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin']` matches nothing, append `<Relationship Id="rel-id-<UUID>" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin" Target="_xmlsignatures/origin.sigs"/>`; serialize.
- any entry whose name starts with `_xmlsignatures/_rels/` and ends with `.rels` (normally `origin.sigs.rels`): set `hasOriginSigsRels`; append `<Relationship Id="rel-<UUID>" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature" Target="sig-<UUID>.xml"/>` (Target = basename of the new signature entry); serialize.
- anything else: copied byte-for-byte (uncompressed content re-deflated).

After the loop, if no origin rels part existed: add `_xmlsignatures/_rels/origin.sigs.rels` =
`<?xml version="1.0" encoding="UTF-8" standalone="no"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rel-<UUID>" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature" Target="sig-<UUID>.xml"/></Relationships>`
and then an empty (0-byte) `_xmlsignatures/origin.sigs`. Finally add the `_xmlsignatures/sig-<UUID>.xml` entry with the signature XML. No `[Content_Types]` entry is added for the `.rels` (covered by the usual `Default Extension="rels"`). Existing `origin.sigs` is copied unchanged.

Why existing signatures stay valid: `[Content_Types].xml` is never signed; the origin relationship in `_rels/.rels` is excluded from the RelationshipTransform; new relationships in `origin.sigs.rels` have fresh Ids not in older SourceId lists; `_xmlsignatures/*.xml` are never in the signed content dirs.

### Signature discovery (OOXMLUtil)

- `getSignaturesRels`: read `_rels/.rels` (or `_rels\.rels`) with `RelationshipsParser`; take the FIRST relationship of origin type; `middle = Target.substring(0, "_xmlsignatures".length()+1)` (= first 15 chars, assumes Target starts with `_xmlsignatures/`, a leading `/` breaks it), `name = Target.substring(15)`; read `middle + "_rels/" + name + ".rels"` (or with `\`). Missing -> no signatures.
- `countOOXMLSignatures`: number of relationships with signature type in that part; errors -> 0.
- `getOOXMLSignatures`: for each signature relationship (document order) read `"_xmlsignatures/" + Target` (or `_xmlsignatures\` + Target); a missing part -> whole result empty array.
- `RelationshipsParser` is strict: root node name must be `Relationships` and carry a literal `xmlns` attribute equal to the relationships namespace; **every** child node (including whitespace text nodes!) must be named `Relationship` with `Id`, `Type`, `Target` attributes, else `IOException` — so pretty-printed `.rels` files make `isSign` return false.

### OOXML cosign behaviour

`cosign` == `sign` on the signed package: a new independent `sig-<UUID>.xml` is added and referenced from the existing `origin.sigs.rels`. Its Manifest also references `/_xmlsignatures/_rels/origin.sigs.rels` (RelationshipTransform with the Ids of the existing signature relationships — not excluded), thereby protecting the set of earlier signatures; the earlier signature XML parts themselves are not referenced.

### OOXML example (`_xmlsignatures/sig-<UUID>.xml`, docx, SHA256withRSA, 1 CTI, comments)

Whitespace added for readability (actual output has none); digests elided.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="xmldsig-6b0f...-Signature">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#idPackageObject">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/><ds:DigestValue>...</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#idOfficeObject">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/><ds:DigestValue>...</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xmldsig-6b0f...-SignedProperties">
      <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/><ds:DigestValue>...</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#xmldsig-6b0f...-KeyInfo">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/><ds:DigestValue>...</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="xmldsig-6b0f...-SignatureValue">...</ds:SignatureValue>
  <ds:KeyInfo Id="xmldsig-6b0f...-KeyInfo">
    <ds:KeyValue><ds:RSAKeyValue><ds:Modulus>...</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>
    <ds:X509Data><ds:X509Certificate>MIIH...</ds:X509Certificate></ds:X509Data>
  </ds:KeyInfo>
  <ds:Object Id="idPackageObject">
    <ds:Manifest>
      <ds:Reference URI="/_rels/.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml">
        <ds:Transforms>
          <ds:Transform Algorithm="http://schemas.openxmlformats.org/package/2006/RelationshipTransform"
                        xmlns:mdssi="http://schemas.openxmlformats.org/package/2006/digital-signature">
            <mdssi:RelationshipReference SourceId="rId1"/>
          </ds:Transform>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="/word/_rels/document.xml.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml">
        <ds:Transforms>
          <ds:Transform Algorithm="http://schemas.openxmlformats.org/package/2006/RelationshipTransform"
                        xmlns:mdssi="http://schemas.openxmlformats.org/package/2006/digital-signature">
            <mdssi:RelationshipReference SourceId="rId3"/>
            <mdssi:RelationshipReference SourceId="rId2"/>
            <mdssi:RelationshipReference SourceId="rId1"/>
          </ds:Transform>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="/word/document.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="/word/styles.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="/word/media/image1.png?ContentType=image/png">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
    </ds:Manifest>
    <ds:SignatureProperties Id="id-signature-time-1d3e...">
      <ds:SignatureProperty Id="idSignatureTime" Target="#xmldsig-6b0f...">
        <mdssi:SignatureTime xmlns:mdssi="http://schemas.openxmlformats.org/package/2006/digital-signature">
          <mdssi:Format>YYYY-MM-DDThh:mm:ssTZD</mdssi:Format>
          <mdssi:Value>2026-10-16T01:17:05Z</mdssi:Value>
        </mdssi:SignatureTime>
      </ds:SignatureProperty>
    </ds:SignatureProperties>
  </ds:Object>
  <ds:Object Id="idOfficeObject">
    <ds:SignatureProperties>
      <ds:SignatureProperty Id="idOfficeV1Details" Target="#xmldsig-6b0f...">
        <SignatureInfoV1 xmlns="http://schemas.microsoft.com/office/2006/digsig">
          <SetupID/><SignatureText/><SignatureImage/>
          <SignatureComments>RAZON-PRUEBA</SignatureComments>
          <OfficeVersion>16.0</OfficeVersion><ApplicationVersion>16.0</ApplicationVersion>
          <Monitors>1</Monitors>
          <HorizontalResolutionElement>1920</HorizontalResolutionElement>
          <VerticalResolutionElement>1080</VerticalResolutionElement>
          <ColorDepth>32</ColorDepth>
          <SignatureProviderId>{00000000-0000-0000-0000-000000000000}</SignatureProviderId>
          <SignatureProviderUrl/>
          <SignatureProviderDetails>9</SignatureProviderDetails>
          <SignatureType>1</SignatureType>
        </SignatureInfoV1>
        <SignatureInfoV2 xmlns="http://schemas.microsoft.com/office/2006/digsig">
          <Address1>Dir 1</Address1><Address2>Dir 2</Address2>
        </SignatureInfoV2>
      </ds:SignatureProperty>
    </ds:SignatureProperties>
  </ds:Object>
  <ds:Object>
    <xd:QualifyingProperties xmlns:xd="http://uri.etsi.org/01903/v1.3.2#" Id="xmldsig-6b0f...-QualifyingProperties" Target="#xmldsig-6b0f...-Signature">
      <xd:SignedProperties Id="xmldsig-6b0f...-SignedProperties">
        <xd:SignedSignatureProperties>
          <xd:SigningTime>2026-10-16T13:17:05+02:00</xd:SigningTime>
          <xd:SigningCertificate><xd:Cert>
            <xd:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/><ds:DigestValue>...</ds:DigestValue></xd:CertDigest>
            <xd:IssuerSerial><ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName><ds:X509SerialNumber>1234567890</ds:X509SerialNumber></xd:IssuerSerial>
          </xd:Cert></xd:SigningCertificate>
          <xd:SignaturePolicyIdentifier><xd:SignaturePolicyImplied/></xd:SignaturePolicyIdentifier>
          <xd:SignatureProductionPlace><xd:City>Ciudad 1</xd:City><xd:StateOrProvince>Provincia 1</xd:StateOrProvince><xd:PostalCode>CPostal 1</xd:PostalCode><xd:CountryName>Pais 1</xd:CountryName></xd:SignatureProductionPlace>
          <xd:SignerRole><xd:ClaimedRoles><xd:ClaimedRole>Rol</xd:ClaimedRole></xd:ClaimedRoles></xd:SignerRole>
        </xd:SignedSignatureProperties>
        <xd:SignedDataObjectProperties>
          <xd:CommitmentTypeIndication>
            <xd:CommitmentTypeId>
              <xd:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfApproval</xd:Identifier>
              <xd:Description>Aprobó este documento</xd:Description>
            </xd:CommitmentTypeId>
            <xd:AllSignedDataObjects/>
            <xd:CommitmentTypeQualifiers><xd:CommitmentTypeQualifier>RAZON-PRUEBA</xd:CommitmentTypeQualifier></xd:CommitmentTypeQualifiers>
          </xd:CommitmentTypeIndication>
        </xd:SignedDataObjectProperties>
      </xd:SignedProperties>
    </xd:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

(The real `QualifyingProperties` also carries an explicit, redundant `xmlns:ds` declaration; inclusive C14N of SignedProperties therefore renders `xmlns:ds` and `xmlns:xd` on the `xd:SignedProperties` apex.)

For comparison, Word itself (test resource `entrada_w2016_SIGNED.docx`) writes an unprefixed `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="idPackageSignature">`, SHA-256 everywhere, `idSignedProperties`, `sig1.xml`, and `SignatureProperty Target="#idPackageSignature"`; AutoFirma's output differs in all those points but Office accepts it.

### OOXML gotchas

- Digest algorithms are fixed (SHA-512 SignedInfo/XAdES, SHA-256 Manifest) regardless of the requested signature algorithm.
- `ppt/` parts are not referenced (only `"word"`, `"excel"`, `"xl"`, `"powerpoint"` prefixes): PowerPoint content is effectively unsigned apart from relationship parts. `docProps/*` never signed.
- `mdssi:Value` uses a local 12-hour clock with a fake `Z`; `SignatureProperty/@Target` points to `#xmldsig-<uuid>` while the Signature Id is `xmldsig-<uuid>-Signature`.
- `idOfficeObject` content depends on the environment (OS, monitors, screen resolution, color depth); headless Java fails.
- The certificate chain is reduced to the signer certificate; `includeOnlySignningCertificate`, `signatureReason`, `signerClaimedRole` are not honoured.
- Relationship transform: only SourceId selection; sort by Id with plain string order; TargetMode default `Internal`.
- ZIP: all entries re-deflated with new timestamps; new entries appended at the end (`origin.sigs.rels`, `origin.sigs`, `sig-<UUID>.xml`).
- `RelationshipsParser` rejects `.rels` with whitespace nodes, making detection fail on pretty-printed packages.
- `sign()` requires `docProps/app.xml` and `docProps/core.xml` to exist.

---

### Parity checklist rows (ODF / OOXML)

| Feature | Java class / method | Notes |
|---|---|---|
| ODF data detection | `AOODFSigner.isValidDataFile` / `getODFMimeType` | ZIP magic + exact `mimetype` content in {text, spreadsheet, presentation}. |
| ODF signed detection | `AOODFSigner.isSign` | valid ODF + `META-INF/documentsignatures.xml` entry exists. |
| ODF reference list | `AOODFSigner.sign` | mimetype + manifest (3.2+ only), manifest file-entries (4 root XMLs C14N, rest raw), `#SignatureProperty`. |
| ODF digest param | `AOODFExtraParams.REFERENCES_DIGEST_METHOD` | default SHA-1 URI; sha256/sha512 URIs; sha384 URI fails. |
| ODF OOo 3.1 mode | `AOODFExtraParams.USE_OPEN_OFFICE_31_MODE` | no mimetype/manifest refs; manifest gets 2 file-entries when signatures file is new. |
| ODF SignatureMethod | `AOODFSigner.sign` | always `rsa-sha1`; `algorithm` ignored. |
| ODF C14N of parts | `OdfXmlUtil.canonicalizeXml` (XOM) | inclusive C14N 1.0 of document element. |
| ODF dc:date | `AOODFSigner.sign` | `yyyy-MM-dd'T'HH:mm:ss,SS`, local, no TZ. |
| ODF KeyInfo | `AOODFSigner.sign` | X509SubjectName (RFC 2253) + X509Certificate (signer only). |
| ODF cosign | `AOODFSigner.cosign` -> `sign` | append Signature to existing `document-signatures`. |
| ODF countersign | `AOODFSigner.countersign` | `UnsupportedOperationException`. |
| ODF ZIP rewrite | `AOODFSigner.sign` (ZipOutputStream) | copy all but signatures/manifest (DEFLATED, new timestamps), then signatures, then manifest. |
| ODF signers tree | `AOODFSigner.getSignersStructure` | root "Datos"; CN or AOSimpleSignInfo per Signature; error -> "Raíz". |
| ODF signed name | `AOODFSigner.getSignedName` | .odt/.odp/.ods kept, else `.odf`. |
| OOXML data detection | `AOOOXMLSigner.isValidDataFile` / `OfficeAnalizer.isOOXMLDocument` | 4 mandatory entries (backslash variants only in isValidDataFile). |
| OOXML signed detection | `OOXMLUtil.countOOXMLSignatures` | `_rels/.rels` origin rel -> origin rels -> count signature rels; strict parser. |
| OOXML signature ids | `OOXMLXAdESSigner.getSignedXML`, jxades `XMLAdvancedSignature` | prefix `xmldsig-<uuid>`; `-Signature`, `-SignatureValue`, `-KeyInfo`, `-QualifyingProperties`, `-SignedProperties`. |
| OOXML SignedInfo refs | `OOXMLXAdESSigner` + `OOXMLAdvancedSignature.sign` | `#idPackageObject`, `#idOfficeObject` (Type Object), SignedProperties (C14N transform), KeyInfo; all SHA-512. |
| OOXML Manifest | `OOXMLPackageObjectHelper.constructManifest` | .rels refs with RelationshipTransform+C14N, then content parts under word/excel/xl/powerpoint with Override/Default content type; SHA-256; dedup by URI. |
| OOXML excluded rel types | `OOXMLPackageObjectHelper.EXCLUDED_RELATIONSHIPS` | extended-properties, core-properties, origin, thumbnail, presProps, viewProps. |
| OOXML SignatureTime | `OOXMLPackageObjectHelper.addSignatureTime` | `yyyy-MM-dd'T'hh:mm:ss'Z'` local 12h; Ids `idSignatureTime`, `id-signature-time-<uuid>`. |
| OOXML Office object | `OOXMLOfficeObjectHelper.getOfficeObject` | SignatureInfoV1 (fixed + env values) + SignatureInfoV2 (addresses); Id `idOfficeV1Details`. |
| OOXML XAdES props | jxades `ExplicitPolicyXAdESImpl` / `BasicXAdESImpl.marshalQualifyingProperties` | v1.3.2 ns, prefix `xd`; SigningTime, SigningCertificate (SHA-512), SignaturePolicyImplied, SignatureProductionPlace, SignerRole, CTIs. |
| OOXML CTIs | `XAdESUtil.parseCommitmentTypeIndications(xParams, null)` | indices 0..n inclusive, `AllSignedDataObjects`; sets SignatureType=1. |
| OOXML KeyInfo | `OOXMLAdvancedSignature.newKeyInfo` | KeyValue + X509Data(signer cert). |
| RelationshipTransform | `relprovider.RelationshipTransformService` | filter by SourceId, drop non-elements, default TargetMode=Internal, sort by Id, serialize, then C14N. |
| OOXML URI dereferencing | `OOXMLURIDereferencer` | URL-decode, strip `/` and `?query`, raw ZIP entry bytes; else default dereferencer. |
| OOXML package update | `OOXMLZipHelper.copyOOXMLContent` | Content_Types Override (+Default sigs), `_rels/.rels` origin rel, origin.sigs.rels (+new), empty origin.sigs, `sig-<uuid>.xml` last. |
| OOXML signature serialization | `OOXMLXAdESSigner.writeXML` | LSSerializer, namespaces=false, UTF-8. |
| OOXML signers tree | `AOOOXMLSigner.getSignersStructure` | per-signature `AOXAdESSigner.getSignersStructure`, child 0 of each. |
| OOXML cosign/countersign | `AOOOXMLSigner.cosign` / `countersign` | cosign == sign; countersign unsupported. |
| OOXML signed name | `AOOOXMLSigner.getSignedName` | .docx/.xlsx/.pptx/.ppsx kept else `.ooxml`. |

---

## 9. XML signature validation (`afirma-crypto-validation`)

Sources: `afirma-crypto-validation/src/main/java/es/gob/afirma/signvalidation/`
`SignValiderFactory`, `SignValider`, `ValidateXMLSignature`, `SignValidity`,
`ISignatureFormatDetector`, `SignatureFormatDetectorXades`, `DataAnalizerUtil`, `ValidationMessages`
(bundle `validationmessages/validationmessages_<locale>.properties`).

There is **no** validator for ODF or OOXML (factory returns `null`). FacturaE and any XML go to
`ValidateXMLSignature`.

### Validator selection (`SignValiderFactory.getSignValider(byte[] data)`)

Order of checks (first match wins); `data == null || data.length < 1` -> `IllegalArgumentException`.

| # | Check (`DataAnalizerUtil`) | Implementation | Result |
|---|---|---|---|
| 1 | `isPDF(data)` | `new AOPDFSigner().isValidDataFile(data)` | `ValidatePdfSignature` |
| 2 | `isFacturae(data)` | `new AOFacturaESigner().isValidDataFile(data)` | `ValidateXMLSignature` |
| 3 | `isXML(data)` | `AOFileUtils.isXML(data)` (secure SAX parse succeeds) | `ValidateXMLSignature` |
| 4 | `isOOXML(data)` | `new AOOOXMLSigner().isValidDataFile(data)` | `null` (warning "No hay un validador para OOXML") |
| 5 | `isODF(data)` | `new AOODFSigner().isValidDataFile(data)` | `null` |
| 6 | otherwise | | `ValidateBinarySignature` |

`getSignValider(AOSigner signer)`: `AOCAdESSigner` -> binary; `AOXAdESSigner` or `AOFacturaESigner` -> XML;
`AOPDFSigner` -> PDF; anything else (incl. `AOXMLDSigSigner`, ODF, OOXML) -> `null`.

Other XML-related helpers in `DataAnalizerUtil`:
- `isSignedXML(data)` = `new AOXAdESSigner().isSign(data) || new AOXMLDSigSigner().isSign(data)` (exceptions -> false).
- `isSignedFacturae(data)` = `new AOFacturaESigner().isSign(data)`.
- `isSignedODF` / `isSignedOOXML` = respective `isSign`.

### `SignValider` base class

- Field `relaxed` (default false) with `setRelaxed/isRelaxed` (not used by the XML validator).
- `validate(byte[])`, `validate(byte[], boolean checkCertificates)`, `validate(byte[], Properties)`.
  `ValidateXMLSignature` ignores `Properties` entirely and **always** uses `checkCertificates = true`
  for the 1-arg and Properties overloads.
- `checkLongStandingValiditySign(list)` (protected static): if the list contains **only** KO entries whose
  error is `CERTIFICATE_EXPIRED` (no other KO type) **and** an `UNKNOWN/SIGN_PROFILE_NOT_CHECKED` entry,
  then swap that UNKNOWN entry into index 0 (exchanging places with whatever was at index 0).
  Purpose: a long-term (XAdES-T/XL/A) signature whose cert expired is reported as "incomplete validation"
  first instead of "invalid".
- `checkValidityKOPriority(list)` (not used by XML validator): dedupe, KO entries moved to front.

### `ValidateXMLSignature.validate(byte[] sign, boolean checkCertificates)` - exact algorithm

```
result = []
doc = SecureXmlBuilder.getSecureDocumentBuilder().parse(sign)        # namespace-aware, DOCTYPE forbidden
  on any exception -> return [KO / NO_SIGN]
nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature")   # ALL ds:Signature, document order,
                                                                                     # incl. nested CounterSignature
                                                                                     # signatures and XMLTimeStamp sigs
if nl empty -> return [KO / NO_SIGN]
noMatchDataOcurred = false; certExpiredOcurred = false; certNotValidYetOcurred = false (never set!)
try:
  for each sigElem in nl:
    ctx = DOMValidateContext(KeyValueKeySelector, sigElem); ctx.uriDereferencer = CustomUriDereferencer
    sig = XMLSignatureFactory("DOM").unmarshalXMLSignature(ctx)
    if !sig.validate(ctx) && !noMatchDataOcurred:            # JSR-105 core validation (SignatureValue + all refs)
        result += KO/NO_MATCH_DATA; noMatchDataOcurred = true
    if !sig.getSignatureValue().validate(ctx) && !noMatchDataOcurred:
        result += KO/NO_MATCH_DATA; noMatchDataOcurred = true
    for each ref in sig.SignedInfo.References:               # NOT guarded by noMatchDataOcurred:
        if !ref.validate(ctx): result += KO/NO_MATCH_DATA     #   one entry per failing reference (duplicates!)
    if checkCertificates:
        sig2 = unmarshal again; for each X509Data in KeyInfo: for each X509Certificate (ALL certs, chain included):
            cert.checkValidity()  # against current system time
              CertificateExpiredException     -> once: KO/CERTIFICATE_EXPIRED (with exception)
              CertificateNotYetValidException -> every time: KO/CERTIFICATE_NOT_VALID_YET
    profile = SignatureFormatDetectorXades.resolveSignerXAdESFormat(sigElem)
    if profile not in {"XAdES B-Level", "No reconocido", "XAdES B-B-Level", "XAdES-BES", "XAdES-EPES"}:
        result += UNKNOWN/SIGN_PROFILE_NOT_CHECKED
catch XMLSignatureException e -> result += KO/BAD_BUILD_SIGN(e)
catch Exception e            -> result += UNKNOWN/UNKOWN_ERROR(e)       # e.g. MarshalException, KeySelectorException
result = checkLongStandingValiditySign(result)
if result empty -> result = [OK / null]
return result
```

Notes for parity:
- A failure anywhere aborts the loop (remaining signatures are not validated).
- KeyInfo must be present when `checkCertificates` is true: `keyInfo.getContent()` on a null KeyInfo
  throws NPE -> caught as `UNKNOWN/UNKOWN_ERROR`.
- Only X509Certificate entries in X509Data are checked; no chain building, no revocation, no trust anchors,
  no check that SigningCertificate digest matches the KeyInfo cert. Purely: crypto core validation +
  date validity of embedded certs + profile level.
- XAdES `SignedProperties` references (`URI="#...-SignedProperties"`) are resolvable only through the
  custom dereferencer fallback because the DOM never registers `Id` attributes as XML IDs.

#### `KeyValueKeySelector` (key used to verify)

Iterate `KeyInfo` children in document order:
1. first `ds:KeyValue` -> its public key (RSAKeyValue/DSAKeyValue/ECKeyValue) is returned immediately;
2. else first `ds:X509Data` containing an `X509Certificate` -> **first** certificate's public key.
If KeyInfo is null -> `KeySelectorException("Objeto KeyInfo nulo")`; nothing found ->
`KeySelectorException("No se ha encontrado la clave publica dentro del XML firmado")`.
It also (re)installs `CustomUriDereferencer` on the context.
Consequence: AutoFirma-generated signatures place `X509Data` before `KeyValue` (newer) or `KeyValue` first
(older, e.g. `firmaAfirma.xsig`) - both resolve to the signer key. No check that KeyValue matches the cert.

#### `CustomUriDereferencer` behaviour during validation (core-xml, summary)

Try the platform default dereferencer first. If it throws:
- URI starting with `http://` or `https://`: download with `UrlHttpManager` GET, parse as XML (secure
  builder) and return it as node-set/octet data (so remote XML references can validate; non-XML remote
  content fails).
- URI `""`: whole document (enveloped).
- `#id` / `id`: scan every element (`getElementsByTagName("*")`) for an attribute whose **name**
  equalsIgnoreCase `"Id"` (so `Id`, `ID`, `id`) with that exact value; return it (wrapped as Apache
  `XMLSignatureInput` -> node set, or octet stream).
- not found -> rethrow (`URIReferenceException`).

### `ValidateXMLSignature.validateSign(Element signElement, String signProfile, boolean isExternalDetached)` (static)

Used by the AutoFirma desktop "signature details" analyzers (per-signature validation):
- If `isExternalDetached` -> `[UNKNOWN / CANT_VALIDATE_EXTERNALLY_DETACHED]` and nothing else.
- Else same crypto checks as above (core validate, SignatureValue validate, each Reference) but aggregated:
  at most **one** `KO/NO_MATCH_DATA`; XMLSignatureException -> `KO/BAD_BUILD_SIGN`; other ->
  `UNKNOWN/UNKOWN_ERROR`. No certificate date checks.
- If profile not in the "checked" set -> add `UNKNOWN/SIGN_PROFILE_NOT_CHECKED`, valid=false.
- If nothing failed -> `[OK]`.

### Result model (`SignValidity`)

`SignValidity { validity: SIGN_DETAIL_TYPE, error: VALIDITY_ERROR?, errorException: Exception?, errorCode: ErrorCode? }`
(`errorCode` taken from the exception if it is an `AOControlledException`).

`SIGN_DETAIL_TYPE`: `OK`, `KO`, `UNKNOWN`, `PENDING_CONFIRM_BY_USER`, `GENERATED`.

`VALIDITY_ERROR` (ordinal order) and `toString()` message key (`SignValidationMessage.N`, en_US text):

| VALIDITY_ERROR | key | en_US text | Used by XML validator |
|---|---|---|---|
| NO_DATA | .4 | Validity cannot be checked for lack of signed data | no |
| CORRUPTED_SIGN | .5 | The information contained in the firm is not consistent (corrupt certificates, etc.) | no |
| NO_MATCH_DATA | .6 | Signature does not correspond to signed data | yes |
| NO_SIGN | .7 | No signature found within document | yes |
| CERTIFICATE_PROBLEM | .8 | no certificate can be drawn or this is not valid | no |
| CERTIFICATE_EXPIRED | .9 | there is an expired signing certificate | yes |
| CERTIFICATE_NOT_VALID_YET | .10 | there is a certificate of signature that is not yet valid; | yes |
| CANT_VALIDATE_CERT | .11 | failed to validate the certificate correctly | no |
| ALGORITHM_NOT_SUPPORTED | .12 | The signature contains an unrecognised or unsupported algorithm | no |
| CA_NOT_SUPPORTED | .13 | Dispatch CA not supported | no |
| CRL_PROBLEM | .14 | There is some problem with CRLs embedded in the firm | no |
| PDF_UNKOWN_VALIDITY | .15 | ... PDF | no |
| OOXML_UNKOWN_VALIDITY | .16 | The validity of OOXML signature cannot be checked | no |
| ODF_UNKOWN_VALIDITY | .17 | The validity of ODF signature cannot be verified | no |
| UNKOWN_ERROR | .18 | The validity of the signature cannot be checked | yes |
| UNKOWN_SIGNATURE_FORMAT | .19 | the data provided does not correspond to any recognised signature format | no |
| MODIFIED_FORM | .22 | a document form was modified after signing | no |
| MODIFIED_DOCUMENT | .20 | The PDF document is suspected of having been modified after signature. | no |
| OVERLAPPING_SIGNATURE | .21 | the signatures of the document overlap and can hide information | no |
| SUSPECTED_SIGNATURE | .23 | The document is suspicious and the user must check the signature | no |
| SIGN_PROFILE_NOT_CHECKED | .24 | The signature contains long-lived attributes that Autofirma cannot validate. For a full validation, it relies on VALIDe. | yes |
| CANT_VALIDATE_EXTERNALLY_DETACHED | .25 | Validation of signatures with external references is not permitted | yes (validateSign) |
| BAD_BUILD_SIGN | .26 | The signature is not properly formed | yes |
| CERTIFIED_SIGN_REVISION | .27 | The certified document did not allow new signatures | no |

Type prefix (`validityTypeToString`): OK/GENERATED -> `.0` "Valid signature"; UNKNOWN -> `.1` "Incomplete validation";
PENDING_CONFIRM_BY_USER -> `.2` "Validity to be confirmed by the user"; KO -> `.3` "Invalid signature".
`toString()` = `"<type text>: <error text>"`. Spanish (es_ES) strings exist and are the default UI locale
(e.g. `.6` = "la firma no se corresponde con los datos firmados").

Callers typically look only at `result.get(0)` (e.g. tri-phase server: if `get(0).validity == KO` ->
`InvalidSignatureException("La firma que se trata de cofirmar no es valida: " + error)`).

### XAdES profile/level detection (`SignatureFormatDetectorXades`)

Format strings (`ISignatureFormatDetector`, exact values):
`"No reconocido"`, `"XAdES-BES"`, `"XAdES-EPES"`, `"XAdES-T"`, `"XAdES-C"`, `"XAdES-X1"`, `"XAdES-X2"`,
`"XAdES-XL1"`, `"XAdES-XL2"`, `"XAdES-A"`, `"XAdES B-Level"`, `"XAdES B-B-Level"`, `"XAdES T-Level"`,
`"XAdES LT-Level"`, `"XAdES LTA-Level"`. (CAdES/PAdES/ASiC equivalents also exist, e.g. `"ASiC-S B-Level"`.)

Namespaces used: `NS132 = "http://uri.etsi.org/01903/v1.3.2#"`, `NS141 = "http://uri.etsi.org/01903/v1.4.1#"`,
`DS = "http://www.w3.org/2000/09/xmldsig#"`. **Only v1.3.2 (and 1.4.1 for TimeStampValidationData) is
recognised**; XAdES 1.2.2 / 1.1.1 signatures are generally "No reconocido" (see fallback below).

Helper `getXMLElement(parent, ns, name)` = first descendant (any depth!) `getElementsByTagNameNS(ns, name)`;
if none, fallback `getElementsByTagName(name)` - i.e. matches elements whose **qualified name** is exactly
`name` (unprefixed elements in any namespace). All "has element" tests are therefore *descendant* searches
under the `ds:Signature`, which means properties of nested countersignatures also count.

Per-signature predicates (S = a `ds:Signature` element):

| Predicate | Rule (all element lookups are descendant searches) |
|---|---|
| `isXAdESBES(S)` | `getXMLElement(S, NS132, "QualifyingProperties") != null` |
| `isXAdESEPES(S)` / `hasSignaturePolicyIdentifier(S)` | SP=`getXMLElement(S,NS132,"SignedProperties")`; SSP=`getXMLElement(SP,NS132,"SignedSignatureProperties")`; `getXMLElement(SSP,NS132,"SignaturePolicyIdentifier") != null` |
| `isXAdESBLevel(S)` | S has **no** NS132 `QualifyingPropertiesReference`; S has NS132 `SignedProperties` (first); it contains NS132 `SignedSignatureProperties` (the *first one under S* is then used) with NS132 `SigningCertificate` **and** NS132 `SigningTime`; first NS132 `SignedDataObjectProperties` under SP has a `DataObjectFormat` (getXMLElement) that contains NS132 `MimeType`. All four required. |
| `isXAdESBBLevel(S)` | Same as B-Level but requires NS132 `SigningCertificateV2` instead of `SigningCertificate`. |
| `isXAdEST(S)` | NS132 `UnsignedProperties` -> NS132 `UnsignedSignatureProperties` -> NS132 `SignatureTimeStamp` present |
| `isXAdESC(S)` | USP has both NS132 `CompleteCertificateRefs` and `CompleteRevocationRefs` |
| `isXAdESX1(S)` | USP has NS132 `SigAndRefsTimeStamp` |
| `isXAdESX2(S)` | USP has NS132 `RefsOnlyTimeStamp` |
| `isXAdESXL1(S)` | USP has `SigAndRefsTimeStamp` + `CertificateValues` + `RevocationValues` (NS132) |
| `isXAdESXL2(S)` | USP has `RefsOnlyTimeStamp` + `CertificateValues` + `RevocationValues` (NS132) |
| `isXAdESA(S)` = `isXAdESLTALevel(S)` | a **direct child element** of USP whose localName is `ArchiveTimeStamp` (any namespace: matches both xades:1.3.2 and xadesv141:ArchiveTimeStamp) |
| `isXAdESLTLevel(S)` | Computes flags from USP: CertificateValues, RevocationValues, NS141 `TimeStampValidationData`, CompleteCertificateRefs, CompleteRevocationRefs, AttributeCertificateRefs, AttributeRevocationRefs, SigAndRefsTimeStamp, RefsOnlyTimeStamp. LT iff `(hasCertValues && hasRevValues \|\| hasTSValidationData) && none of the 6 "refs/X" elements`. **Bug to replicate:** the RevocationValues lookup is assigned to `hasCertificateValues` and `hasRevocationValues` is a constant `false`, so effectively LT iff `TimeStampValidationData` present and none of the six refs/X elements present. |

`resolveSignerXAdESFormat(S)` (the per-signature API used by validators):
```
if S == null -> "No reconocido"
if isXAdESEPES(S):  f = baseline("XAdES-EPES", S); if f == "XAdES-EPES": f = noBaseline("XAdES-EPES", S)
elif isXAdESBES(S): f = baseline("XAdES-BES",  S); if f == "XAdES-BES":  f = noBaseline("XAdES-BES",  S)
else f = "No reconocido"

baseline(tmp, S):
  if isXAdESBLevel(S):
      f = "XAdES B-Level"
      if isXAdEST(S):
          f = "XAdES T-Level"
          if isXAdESLTLevel(S):
              f = "XAdES LT-Level"; if isXAdESA(S): f = "XAdES LTA-Level"
          else: noBaseline(f, S)        # result DISCARDED (bug): stays "XAdES T-Level"
      return f
  elif isXAdESBBLevel(S): return "XAdES B-B-Level"
  return tmp

noBaseline(tmp, S):   # first match wins
  A -> "XAdES-A"; XL1 -> "XAdES-XL1"; XL2 -> "XAdES-XL2"; X1 -> "XAdES-X1"; X2 -> "XAdES-X2";
  C -> "XAdES-C"; T (and tmp != "XAdES T-Level") -> "XAdES-T"; else tmp
```
Consequences: a normal AutoFirma XAdES (SigningCertificate + SigningTime + DataObjectFormat/MimeType) is
"XAdES B-Level" whether or not it has a policy; with SigningCertificateV2 it is "XAdES B-B-Level"; a B-level
signature with SignatureTimeStamp is "XAdES T-Level" (even if it also has XL/A refs, unless
TimeStampValidationData); a signature lacking MimeType in DataObjectFormat but with SignatureTimeStamp
is "XAdES-T".

Validator "checked" set = {B-Level, "No reconocido", B-B-Level, XAdES-BES, XAdES-EPES}. Anything else
(T, C, X1, X2, XL1, XL2, A, T/LT/LTA-Level) yields `UNKNOWN/SIGN_PROFILE_NOT_CHECKED`.

Document-level `getSignatureFormat(byte[] signature)` (used by format detection, not by the validator):
- If not `AOFileUtils.isXML` -> "No reconocido".
- Parse with `Utils.getNewDocumentBuilder()`; `getListSignatures(doc)` = all `DS:Signature` elements
  except those whose parent localName is `"XMLTimeStamp"` (`TAG_XML_TIMESTAMP` and `TAG_TIMESTAMP` both
  equal `"XMLTimeStamp"`).
- EPES if **any** signature has a policy; else BES if any has QualifyingProperties.
- List versions of the predicates are "any signature matches", **except** `isXAdESBLevel(list)` which
  returns the result for the **first** signature only (loop returns on first iteration), and the list
  version has no B-B-Level branch.
- Any exception -> "No reconocido".
- `isXAdESBaseline(fmt)` = fmt in {B-Level, T-Level, LT-Level, LTA-Level}.

### Validation use in the XAdES signers / tri-phase

- Tri-phase server `XAdESTriPhasePreProcessor.preProcessPreCoSign/PreCounterSign` with `checkSignatures=true`
  runs `new ValidateXMLSignature().validate(data)` and aborts if `result[0].validity == KO`.
- The validation module imports `es.gob.afirma.signers.xades.XAdESConstants` for tag/namespace names.

---

## 10. Tri-phase (pre/post) split for XAdES (`afirma-crypto-xadestri-client` + server core)

Client classes: `es.gob.afirma.signers.xadestri.client.AOXAdESTriPhaseSigner` (format `"XAdES"`),
`AOFacturaETriPhaseSigner` (format `"FacturaE"`), `asic.AOXAdESASiCSTriPhaseSigner`
(format `"XAdES-ASiC-S"`). Server classes (module `afirma-server-triphase-signer-core`):
`processors.XAdESTriPhasePreProcessor`, `processors.FacturaETriPhasePreProcessor`,
`processors.XAdESASiCSTriPhasePreProcessor`, `processors.XAdESTriPhaseSignerUtil`,
`xades.XAdESTriPhaseSignerServerSide`, `xades.KeyHelper{Rsa,Ecdsa}`, `core.signers.TriphaseData`,
`core.signers.TriphaseDataSigner`.

Key idea: **the client never touches XML.** The server builds a complete XAdES signature with a throw-away
key, extracts the canonicalized `SignedInfo` of each new `ds:Signature` (that is what the client signs with
PKCS#1), and keeps the signed XML as a template with placeholders. Post-sign substitutes the real
PKCS#1 values into the template.

### Client protocol (`AOXAdESTriPhaseSigner.triPhaseOperation`)

Mandatory: `extraParams != null`, `key != null`, `certChain` non-empty, `data != null` unless
`!isDataMandatory` where `isDataMandatory(cop, cfg) = cop != "sign" || cfg == null ||
(cfg.format != "XAdES Externally Detached" && !Boolean(cfg.useManifest))`.

Client-only extraParams (removed from the forwarded copy): `serverUrl` (required, must parse as URL),
`validatePkcs1`. Also read: `servicetimeout` (int ms, read timeout for post-sign only),
`includeOnlySignningCertificate` (affects `cert` param). Countersign adds `target` = `"tree"` | `"leafs"`
(`CounterSignTarget.toString()`); other targets -> IllegalArgumentException.
`AOXAdESTriPhaseSigner.cosign(data, sign, ...)` sends **`sign`** as `doc` (data ignored).
FacturaE tri-phase: cosign/countersign -> `UnsupportedOperationException("No se soporta la multifirma de las firmas FacturaE")`.
ASiC-S tri-phase: countersign unsupported; getSignedName -> `<name><inText>.asics`. Others -> `.xsig`.
`getData`, `getSignersStructure`, `getSignInfo` -> `UnsupportedOperationException`.
`isSign`: parse (secure) and true iff root or any descendant is `{DS}Signature`. FacturaE: `super.isSign && isValidDataFile`
(root localName `Facturae` with child localNames `FileHeader`, `Parties`, `Invoices`). ASiC: extract
`META-INF/signatures.xml`-style entry via `ASiCUtil.getASiCSXMLSignature` then `super.isSign`.

HTTP request (both phases POST to `serverUrl` with query-string-style params; the HTTP manager posts them):

| param | pre | post | value |
|---|---|---|---|
| `op` | `pre` | `post` | phase |
| `cop` | yes | yes | `sign` / `cosign` / `countersign` |
| `format` | yes | yes | `XAdES`, `FacturaE`, `XAdES-ASiC-S` (signer format) |
| `algo` | yes | yes | Java algorithm name e.g. `SHA256withRSA` |
| `cert` | yes | yes | URL-safe Base64 DER of `certChain[0]` if `includeOnlySignningCertificate=true` (or extraParams null), else all certs URL-safe Base64 joined with `,` |
| `doc` | if data | if data | URL-safe Base64 of data (or of the signature for cosign/countersign) |
| `params` | if non-empty | if non-empty | `AOUtil.properties2Base64(xParams)`: `Properties.store()` text, UTF-8, URL-safe Base64 |
| `session` | - | yes | URL-safe Base64 of the TriphaseData XML returned by pre (after client signing) |

Responses: if length <= 8 -> error (`MALFORMED_*_RESPONSE`). If first 8 bytes start with `"ERR-"` -> server
error `ERR-<code>:<msg>[:<exceptionClass>:<msg>]`; `ERR-21:<subcode>:<msg>` = "config needed"
(maps to `NotFoundXPathException`, `SigningLTSException`, `SignaturePolicyIncompatibilityException` by
`REQUESTOR_*_MSG_CODE`). Pre success body = Base64 of the TriphaseData XML, decoded by the client with the **URL-safe** alphabet
(`Base64.decode(bytes, 0, len, true)`) - the server must emit URL-safe Base64.
Post success body = `OK NEWID=<base64>`; the client returns `Base64.decode(substring after "OK NEWID=")`
(the final signature, or an id, depending on server storage config).

TriphaseData XML (`TriphaseData.toString()` / `parser`):
```xml
<xml>
 <firmas format="XAdES">            <!-- format attribute optional -->
  <firma Id="<signatureId>">        <!-- optional signid="..." attribute -->
   <param n="PRE">BASE64</param>
   <param n="NEED_PRE">true</param>
   <param n="BASE">BASE64</param>   <!-- only in the first <firma> -->
   <param n="ENCODING">UTF-8</param><!-- only in the first <firma> -->
   <param n="PK1_DECODED">true</param><!-- only for DSA/ECDSA -->
  </firma>
 </firmas>
</xml>
```
Root element name is irrelevant; the first child element must be named `firmas` (case-insensitive);
each element child of `firmas` is a sign; each element child of a sign must have attribute `n`, value = trimmed
text content. Param order is a hash map order (not significant).

Client signing step (`TriphaseDataSigner.doSign`): for each `firma`: `PRE` (Base64) -> bytes; signature
algorithm = `composeSignatureAlgorithmName(algo, key.getAlgorithm())`; `PK1` = Base64(standard) of the
PKCS#1 signature (`AOPkcs1Signer.sign(preBytes, sigAlg, key, chain, extraParams)` - i.e. hash-and-sign of the
SignedInfo bytes; ECDSA produces DER `SEQUENCE{r,s}`). Then delete `PRE` unless `NEED_PRE == "true"`
(XAdES always sets NEED_PRE=true, so PRE is sent back). Errors: no signs -> `PRESIGNS_NOT_FOUND`; missing PRE
-> `MALFORMED_PRESIGN_RESPONSE`.

### Server pre-sign (`XAdESTriPhasePreProcessor.preProcessPre` + `XAdESTriPhaseSignerServerSide.preSign`)

1. Algorithm must be a key of `XMLConstants.SIGN_ALGOS_URI` else `AOException("El formato de firma XAdES no soporta el algoritmo de firma " + algo)`.
2. FacturaE: data must be a valid invoice (`InvalidEFacturaDataException`) and unsigned
   (`EFacturaAlreadySignedException`); params replaced by `AOFacturaESigner.getFacturaEExtraParams(extraParams)`.
3. `preSign(data, algo, certChain, xParams, op)`:
   - If `data` is XML: parse (plain namespace-aware DBF), remember `xmlEncoding = doc.getXmlEncoding()` (default `"UTF-8"`).
     For `op == SIGN`: if the root is `ds:Signature` or any `ds:Signature` exists -> `AOException("El XML ya esta firmado...")`
     (`TRI_SIGNING_SIGNATURE`). Collect the `Id` attribute of every existing `ds:Signature` (previousSignaturesIds).
     For COSIGN/COUNTERSIGN without `useManifest=true`: if the first signature has a hash-manifest reference
     (`XAdESUtil.hasHashManifestReference`) set `useManifest=true`.
   - Non-XML data with COSIGN/COUNTERSIGN -> `AOInvalidSignatureFormatException`.
   - Copy params; set internal param `XAdESExtraParams.INTERNAL_VALIDATE_PKCS1 = "false"`.
   - Dummy private key matching the cert public key type/size: RSA -> random keypair of the same modulus
     bit length (cached per size); EC -> random keypair on the same named curve (BouncyCastle, cached per curve).
   - Run the normal signer: `XAdESSigner.sign` / `XAdESCoSigner.cosign` / `XAdESCounterSigner.countersign`
     (target `LEAFS` iff param `target` equalsIgnoreCase `"LEAFS"`, else `TREE`; `targets` = null).
   - `xmlResult = new String(result, xmlEncoding)`.
   - For each `ds:Signature` in the result having an `Id` not in previousSignaturesIds (signatures without Id are
     skipped with a warning): unmarshal with a key selector returning the cert public key, set
     `javax.xml.crypto.dsig.cacheReference=true`, call `validate` (forces canonicalization),
     take `SignedInfo.getCanonicalizedData()` bytes (= canonicalized SignedInfo using its
     CanonicalizationMethod) and the raw `SignatureValue` bytes. None found -> `XmlPreSignException`.
   - Placeholders: for signature i, `b64 = Base64(signatureValue)`; search key = `">" + b64[0..60]` (or `">" + b64 + "<"`
     if shorter than 60); `start = indexOf(key) + 1`, `end = indexOf('<', start)`; then
     `xmlResult = xmlResult.replace(xmlResult[start..end], "====REPLACEME_" + i + "====")` (String.replace = all
     occurrences). If not found: warning and that signature's SignedInfo is **not** added (index i still
     consumed by the loop - indexes can desync).
     NOTE: this textual match assumes the serializer wrote the SignatureValue Base64 exactly as `Base64.encode`
     (no line breaks in the first 60 chars).
   - Return `XmlPreSignResult(xmlResult bytes in xmlEncoding, signedInfos, xmlEncoding)`.
4. `signatureId = extraParams["SignatureId"]` or random UUID (only the `Id` attribute of `<firma>`).
5. For each SignedInfo i build a `firma`: `PRE = Base64(signedInfo_i)`; `PK1_DECODED=true` if
   `isDSAorECDSASignatureAlgorithm(algo)`; `NEED_PRE=true`; for i == 0 also
   `BASE = Base64(removeCommonParts(xmlSign, encoding, extraParams))` and `ENCODING = encoding`.

`removeCommonParts(xml, enc, params)` (size reduction of the template):
- If `useManifest=true` or `format == "XAdES Enveloped"` (equalsIgnoreCase) -> return unchanged.
- Parse; collect "immutable references": for every `ds:Signature` (root included), only references inside its
  `SignedInfo` whose `Type` does **not** end with `#SignedProperties` and that have **no** Transform
  `http://www.w3.org/2000/09/xmldsig#enveloped-signature`; distinct `URI` values in order (KeyInfo refs are
  included!).
- For each URI, dereference by `Id` (`CustomUriDereferencer.getNodeByInternalUriReference`: strips leading `#`,
  attribute-name-equalsIgnoreCase "Id"); external URIs/not found are skipped. Serialize the node
  (`Utils.writeXML`), strip XML declaration and all ` xmlns...="..."` declarations, take the first start tag
  text as open tag, last `<...` as close tag, node name.
- In the original string, locate the open tag (if the namespace-stripped tag is not literally present, search
  candidates starting with `<nodeName` and pick the one whose `Id="..."` matches), then replace the element
  **content** (between end of open tag and matching close tag, skipping nested same-name elements) with
  `"====REPLACE-" + i + "===="`.
  Effect: the data node (`CONTENT`, `ds:Object` with data, KeyInfo content, etc.) is removed from BASE.

### Server post-sign (`XAdESTriPhasePreProcessor.preProcessPost`)

1. No `firma` -> `AOException(MALFORMED_PRESIGN)`.
2. `xmlBase = decode(sign[0].BASE)` using `sign[0].ENCODING` if present (platform default otherwise).
3. For each sign i: `pk1 = PK1` (missing -> IllegalArgumentException); if `PK1_DECODED == "true"`:
   `pk1 = Base64(Pkcs1Utils.decodeSignature(Base64.decode(pk1)))` - DER `SEQUENCE{INTEGER r, INTEGER s}`
   -> raw `r||s`, each **left-padded to k = max(len(r), len(s)) bytes after stripping leading zeros** (not to
   the curve size!) - failures fall back to the original value. Then
   `xmlBase = xmlBase.replace("====REPLACEME_" + i + "====", pk1.trim())`.
4. Re-run `preSign(data, algo, cert, extraParams, op)` (new dummy signature; different random ids/time - only
   the data-node contents are reused).
5. `insertCommonParts(xmlBase, newPreSign.xmlSign, extraParams)`: if manifest or Enveloped -> return xmlBase as is.
   Else compute immutable references of both documents (must be the same count, else IllegalArgumentException),
   take the content of each referenced node from the fresh signature (same delimiter logic) and substitute
   `"====REPLACE-" + i + "===="` in xmlBase. Result bytes in xmlBase's declared encoding.
6. FacturaE: data must again be a valid invoice; params transformed with `getFacturaEExtraParams`.
7. ASiC-S post: params = `AOXAdESASiCSSigner.setASiCProperties(extraParams, data)` + `keepKeyInfoUnsigned=true`
   + `format="XAdES Externally Detached"`; pre-sign is run on `hash(data, precalculatedHashAlgorithm ||
   referencesDigestMethod || DEFAULT_DIGEST_METHOD(SHA-512 URI))` instead of the data; after post-sign the XAdES is packed:
   `ASiCUtil.createSContainer(xades, data, ASiCUtil.ENTRY_NAME_XML_SIGNATURE, extraParams["asicsFilename"])`.
   ASiC co-sign: `UnsupportedOperationException("No se soporta la multifirma de firmas XAdES-ASiC-S")`.

Rust reimplementation hints: the textual placeholder approach depends on Java's serializer output
(attribute order, no whitespace, Base64 without line breaks). A Rust server can instead keep the DOM and
re-serialize, but byte parity with Java tri-phase responses (BASE content) requires replicating:
`====REPLACEME_<i>====` for SignatureValue text and `====REPLACE-<i>====` for removed reference contents.

---

## 11. Constants and core API (`afirma-core`) used by XML signers

### `AOSignConstants` (es.gob.afirma.core.signers)

Format names (`SIGN_FORMAT_*`):

| Constant | Value |
|---|---|
| SIGN_FORMAT_XADES | `XAdES` |
| SIGN_FORMAT_XADES_TRI | `XAdEStri` |
| SIGN_FORMAT_XADES_DETACHED | `XAdES Detached` |
| SIGN_FORMAT_XADES_EXTERNALLY_DETACHED | `XAdES Externally Detached` |
| SIGN_FORMAT_XADES_ENVELOPED | `XAdES Enveloped` |
| SIGN_FORMAT_XADES_ENVELOPING | `XAdES Enveloping` |
| SIGN_FORMAT_XADES_ASIC_S | `XAdES-ASiC-S` |
| SIGN_FORMAT_XADES_ASIC_S_TRI | `XAdES-ASiC-S-tri` |
| SIGN_FORMAT_XMLDSIG | `XMLDSig` |
| SIGN_FORMAT_XMLDSIG_DETACHED | `XMLDSig Detached` |
| SIGN_FORMAT_XMLDSIG_EXTERNALLY_DETACHED | `XMLDSig Externally Detached` |
| SIGN_FORMAT_XMLDSIG_ENVELOPED | `XMLDSig Enveloped` |
| SIGN_FORMAT_XMLDSIG_ENVELOPING | `XMLDSig Enveloping` |
| SIGN_FORMAT_FACTURAE | `FacturaE` |
| SIGN_FORMAT_FACTURAE_TRI | `FacturaEtri` |
| SIGN_FORMAT_FACTURAE_ALT1 | `Factura-e` |
| SIGN_FORMAT_OOXML / _ALT1 | `OOXML (Office Open XML)` / `OOXML` |
| SIGN_FORMAT_ODF / _ALT1 | `ODF (Open Document Format)` / `ODF` |
| SIGN_FORMAT_SOAP | `SOAP` |
| SIGN_FORMAT_AUTO | `auto` |
| DEFAULT_SIGN_FORMAT | `CAdES` |

Modes: `SIGN_MODE_EXPLICIT = "explicit"`, `SIGN_MODE_IMPLICIT = "implicit"`, `DEFAULT_SIGN_MODE = "explicit"`.
Profiles: `SIGN_PROFILE_ADVANCED = "advanced"`, `SIGN_PROFILE_BASELINE = "baseline"`, `DEFAULT_SIGN_PROFILE = "advanced"`.
Massive ops: `FIRMAR`, `COFIRMAR`, `CONTRAFIRMAR_ARBOL`, `CONTRAFIRMAR_HOJAS`.
`DEFAULT_OID_TO_SIGN = "1.3.6.1.4.1.1466.115.121.1.40"`.

Signature algorithms (Java names): `SHA1withRSA`, `SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`,
`NONEwithRSA`, `SHA1withDSA`, `SHA1withECDSA`, `SHA224withECDSA`, `SHA256withECDSA`, `SHA384withECDSA`,
`SHA512withECDSA`, `NONEwithECDSA`. `DEFAULT_SIGN_ALGO = "SHA512withRSA"`.
Digest names: `SHA1`, `SHA256`, `SHA384`, `SHA512`.

`getDigestAlgorithmName(pseudo)` (normalization used everywhere, uppercase compare with Locale.US):
- `"SHA"`, `http://www.w3.org/2000/09/xmldsig#sha1`, `1.3.14.3.2.26`, startsWith `SHA1`/`SHA-1` -> `"SHA1"`
- `http://www.w3.org/2001/04/xmlenc#sha256`, `2.16.840.1.101.3.4.2.1`, startsWith `SHA256`/`SHA-256` -> `"SHA-256"`
- startsWith `SHA384`/`SHA-384`, `2.16.840.1.101.3.4.2.2` -> `"SHA-384"`
- `http://www.w3.org/2001/04/xmlenc#sha512`, `2.16.840.1.101.3.4.2.3`, startsWith `SHA512`/`SHA-512` -> `"SHA-512"`
- `http://www.w3.org/2001/04/xmlenc#ripemd160`, startsWith `RIPEMD160`/`RIPEMD-160` -> `"RIPEMD160"`
- contains `"with"` -> recurse on the part before `"with"` (e.g. `SHA256withRSA` -> `SHA-256`)
- startsWith `http://www.w3.org/2001/04/xmldsig-more#`, `http://www.w3.org/2000/09/xmldsig#`,
  `http://www.w3.org/2009/xmldsig11#` -> recurse on substring after the **last `-`** (e.g. `...#rsa-sha256` -> `sha256`).
  Quirk: `http://www.w3.org/2001/04/xmldsig-more#sha384` -> substring `more#sha384` -> unknown -> returned unchanged (warning).
- otherwise returned unchanged (warning).

`composeSignatureAlgorithmName(algorithm, keyType)` = `getDigestAlgorithmName(algorithm).replace("-","")` +
(`RSA` -> `withRSA`, `DSA` -> `withDSA`, startsWith `EC` -> `withECDSA`, else IllegalArgumentException).
`isSHA2SignatureAlgorithm`, `isSHA1SignatureAlgorithm` (exact name lists), `isDSAorECDSASignatureAlgorithm(a)` =
endsWith `withECDSA` | `withECDSAinP1363Format` | `withDSA` | `withDSAinP1363Format`.

### Signer interfaces (`AOSigner extends AOCoSigner, AOCounterSigner, AOSimpleSigner`)

```
sign(data, algorithm, PrivateKey, Certificate[] chain, Properties extraParams) -> byte[]      // AOSimpleSigner
cosign(data, sign, algorithm, key, chain, extraParams) -> byte[]                            // AOCoSigner
cosign(sign, algorithm, key, chain, extraParams) -> byte[]
countersign(sign, algorithm, CounterSignTarget targetType, Object[] targets, key, chain, extraParams) -> byte[]
getSignersStructure(sign, boolean asSimpleSignInfo) -> AOTreeModel
getSignersStructure(sign, Properties params, boolean asSimpleSignInfo) -> AOTreeModel
isSign(sign) / isSign(sign, Properties params) -> boolean
isValidDataFile(data) -> boolean
getSignedName(originalName, inText) -> String
getData(sign) / getData(sign, Properties params) -> byte[]
getSignInfo(sign) / getSignInfo(data, Properties params) -> AOSignInfo
```
Also `AOConfigurableContext { setSecureMode(bool); isSecureMode() }` and
`OptionalDataInterface { needData(String cryptoOperation, Properties config) }`.

`CounterSignTarget` enum: `SIGNERS("signers")`, `NODES("nodes")`, `TREE("tree")`, `LEAFS("leafs")`;
`toString()` returns the lowercase name; `getTarget(name)` trims and matches case-insensitively, else
IllegalArgumentException("Objetivo no soportado: ...").

Signed file names: XAdES / XMLDSig / FacturaE -> `originalName + (inText ?: "") + ".xsig"`;
XAdES-ASiC-S -> `... + ".asics"`.

### Signers structure (`AOTreeModel` / `AOTreeNode` / `AOSimpleSignInfo`)

- `AOTreeNode { parent, children: List, userObject }`, `add(child)`, `getChildAt(i)`, `getChildCount()`,
  `isLeaf()`, `getUserObject()`, `toString()` = userObject.toString().
- `AOTreeModel(root)`, `getRoot()`, static `getChild(parent, i)`, `getChildCount(parent)`.
- XML signers create root `new AOTreeNode("Datos")` (ODF: empty-structure fallback root `"Raíz"`);
  children = signatures, countersignatures nested under the countersigned signature.
- Node user object: `asSimpleSignInfo ? AOSimpleSignInfo : String CN`.

`Utils.getSimpleSignInfoNode(xadesNamespace, signatureElement)` (core-xml) builds `AOSimpleSignInfo`:
- `signingTime`: if namespace != null, first descendant `{ns}SigningTime`, parsed with
  `SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss")` in the **local default time zone, ignoring the offset suffix**;
  parse failure -> null.
- `certs`: **every** descendant `ds:X509Certificate` (including nested countersignature certs!), text with
  CR/LF/space/tab removed, Base64-decoded X.509; constructor throws if none.
- `signAlgorithm` = `Algorithm` attribute (URI, not Java name) of the first descendant `ds:SignatureMethod`.
- `pkcs1` = Base64-decoded text of the first descendant `ds:SignatureValue` (null on error).
- `signFormat`, `timestampingTime` not set by XML signers.
`Utils.getStringInfoNode(sig)` = CN of the first descendant `ds:X509Certificate` (`AOUtil.getCN`).

`AOSimpleSignInfo` fields: `certs: X509Certificate[]` (non-empty required), `signAlgorithm: String`,
`signFormat: String`, `signingTime: Date`, `timestampingTime: Date[]`, `pkcs1: byte[]`;
`isTimeStamped()` = timestampingTime non-empty and [0] != null; `toString()` = CN + " (" + date + ")".
`AOSignInfo { format, variant, urlSignObject, urlSignedData, b64VerificationCode }`.
`AOTimestampInfo { issuer: X509Certificate, date: Date }`.

### MIME detection (`MimeHelper`) - used by XAdES/XMLDSig when `mimeType` is not given

- Constructor: runs JMimeMagic (`net.sf.jmimemagic.Magic.getMagicMatch(data)` via reflection; dependency
  `afirma-lib-jmimemagic`). `"???"` values -> null. Failures are logged and leave mime null.
- `getMimeType()`:
  1. if already verified return it;
  2. if magic mime is null or `text/xml`: if `AOFileUtils.isXML(data)` set `text/xml` (verified) else clear;
  3. if magic mime is `application/zip` or `application/msword`: `OfficeAnalizer.getMimeType(data)` (ODF/OOXML detection);
  4. **if the magic mime was null -> set `application/octet-stream`** (this also overrides the XML detection of
     step 2 when JMimeMagic returned nothing - quirk: XML undetected by magic becomes octet-stream).
- Constants: `DEFAULT_MIMETYPE = "application/octet-stream"`, `DEFAULT_CONTENT_DESCRIPTION = "binary"`,
  `DEFAULT_CONTENT_OID_DATA = "1.2.840.113549.1.7.1"`.
- `transformMimeTypeToOid(mime)` / `transformOidToMimeType(oid)` from `resources/mimetypes_oids.properties`
  (unknown -> defaults). Table:

| OID | MIME |
|---|---|
| 1.2.840.113549.1.7.1 | `data` |
| 1.2.840.10003.5.109.1 | application/pdf |
| 1.2.840.10003.5.109.2 | application/postscript |
| 1.2.840.10003.5.109.3 | text/html |
| 1.2.840.10003.5.109.4 | image/tiff |
| 1.2.840.10003.5.109.5 | image/gif |
| 1.2.840.10003.5.109.6 | image/jpeg |
| 1.2.840.10003.5.109.7 | image/png |
| 1.2.840.10003.5.109.8 | video/mpeg |
| 1.2.840.10003.5.109.9 | text/sgml |
| 1.2.840.10003.5.109.10 | text/xml |
| 1.2.840.113556.4.2 | application/msword |
| 1.2.840.113556.4.3 | application/vnd.ms-excel |
| 1.2.840.113556.4.4 | application/vnd.ms-project |
| 1.2.840.113556.4.5 | application/vnd.ms-powerpoint |
| 1.2.840.113556.4.6 | application/vnd.ms-works |

  XAdES `DataObjectFormat`: if no OID given, OID = `transformMimeTypeToOid(mime)`, but if mime is not
  `application/octet-stream` and the result is the default data OID, the OID is dropped (no
  ObjectIdentifier). OIDs get the `urn:oid:` prefix and `Qualifier="OIDAsURN"`.

### XML parsing helpers

- `AOFileUtils.isXML(data)`: true iff a secure SAX parse of the whole input succeeds.
- `SecureXmlBuilder.getSecureDocumentBuilder()` / `getSecureSAXParser()`: namespace-aware;
  `FEATURE_SECURE_PROCESSING=true`; external DTD/schema access attributes set to `""`; external general and
  parameter entities disabled (SAX); `http://apache.org/xml/features/disallow-doctype-decl = true`
  (=> **any document with a DOCTYPE is rejected / "not XML"**, see `sample-internal-dtd.xml`).
- `AOUtil.getDataFromInputStream`, `AOUtil.loadFile`, `AOUtil.createURI` (URI building for external refs/styles),
  `AOUtil.getCN(cert)` (CN of subject, used for tree labels).
- `AOUtil.properties2Base64(p)`: `Properties.store(writer UTF-8, "")` -> URL-safe Base64 (`'-'`,`'_'`);
  `base642Properties(s)`: maps `-`->`+`, `_`->`/`, Base64-decodes, loads as UTF-8 properties.

---

## 12. Test resources inventory and repository samples

### 12.1 Inventory (XML-ish test resources)

Legend: detached-int = AutoFirma "internally detached" (`<AFIRMA>` root with sibling `<CONTENT>`); all
XAdES samples use `ds:`/`xades:` prefixes and `http://uri.etsi.org/01903/v1.3.2#` unless stated; C14N =
inclusive `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` unless stated. "SP-ref" = reference with
`Type="http://uri.etsi.org/01903#SignedProperties"`.

#### afirma-crypto-xades/src/test/resources

| File | Content |
|---|---|
| `78353__XAdES_A_Detached.xml` | detached-int, XAdES-A (SignatureTimeStamp, CompleteCertificateRefs, SigAndRefsTimeStamp, CertificateValues, RevocationValues, `xadesv141:ArchiveTimeStamp`); rsa-sha1, refs SHA-512; data ref `Type=...#Object` with C14N transform; KeyInfo ref. |
| `78353__XAdES_A_Enveloping.xml` | enveloping (root `ds:Signature`), XAdES-A; data `ds:Object Id="Object-..." MimeType="text/xml" Encoding="UTF-8"` containing XML `<invoice>`. |
| `XAdES-Detached-SHA1withRSA-B64.xml` | detached-int, EPES, binary content: data ref with `xmldsig#base64` transform, no Type; SHA-1 digests; KeyInfo `KeyValue` before `X509Data` (older output). |
| `XAdES-Detached-SHA1withRSA-XML.xml` / `xades_132_afirma.xml` | detached-int with XML content, EPES, data ref C14N transform. (Identical signature ids.) |
| `XAdES-Enveloped-SHA1withRSA-XML.xml` | enveloped on root `<doc>`; data ref `URI=""` transforms C14N + enveloped-signature + XPath `not(ancestor-or-self::ds:Signature)`. |
| `XAdES-Enveloping-SHA1withRSA-B64.xml` | enveloping, binary: `ds:Object MimeType="application/pdf" Encoding="http://www.w3.org/2000/09/xmldsig#base64"`, ref transform base64, ref `Type=...#Object`. |
| `XAdES-Enveloping-SHA1withRSA-XML.xml` | enveloping, XML content in `ds:Object MimeType="text/xml"` (no Encoding), ref C14N transform. |
| `XAdES-XL_con_sello_binario.xml` | detached-int, XAdES-XL with RFC 3161 `EncapsulatedTimeStamp`s; rsa-sha256. |
| `XAdES-XL_con_sello_xml.xml` | root `<Documento>`, XAdES-XL with **XML timestamps** (`xades:XMLTimeStamp` containing OASIS DSS `ds:Signature` using exc-c14n `http://www.w3.org/2001/10/xml-exc-c14n#`, ref Type `urn:oasis:names:tc:dss:1.0:core:schema:XMLTimeStampToken`) - exercises the XMLTimeStamp exclusion in `getListSignatures`. |
| `externally_detached.xsig` | detached-int root `AFIRMA` but data ref `URI="http://www.africau.edu/images/default/sample.pdf"` (externally detached), no transforms. |
| `firmaAfirma.xsig` | detached-int, base64 data ref, all SHA-1, KeyValue first. |
| `firma_cofirma_xades_longeva.xml`, `firma_cofirma_xades_longeva2.xml` | detached-int with 2 co-signatures over the same `#CONTENT-...`; one is XAdES-A (longeva); rsa-sha256/SHA-512. |
| `firmaIgae.xsig`, `firmaIgae.xsig.xml`, `xades_122_igae.xml` | third-party XAdES **1.2.2** (`etsi:` prefix), root `documentoSGIFE`, ids `Signature001`, `SignedInfo001`, enveloped-signature transform on `#original`, SP-ref Type `http://uri.etsi.org/01903/v1.2.2#SignedProperties`, KeyInfo only X509Data. |
| `firmaMinetad.xsig` | third-party (Minetad) XAdES 1.3.2 with `etsi:` prefix, EPES + SignerRole, numeric ids (`Signature452343`), SHA-256 refs and a `xades:CounterSignature` (reference to `#SignatureValue...`). |
| `sample-factura-firmada-30.xml`, `xades_122_facturae.xml` | FacturaE 3.0 (`http://www.facturae.es/Facturae/2007/v3.0/Facturae`) signed with XAdES 1.2.2, policy + SignerRole, `URI=""` enveloped, `Signature-SignedInfo`, `SignedPropertiesID`, `#Certificate1` KeyInfo ref. |
| `sample-factura-firmada-31.xml`, `sample-facturae-firmada.xsig.xml` | FacturaE 3.1 signed, XAdES 1.3.2 (same "Signature"/"Certificate1" fixed-id style). |
| `sample-factura-firmada-32v1.xsig.xml` | FacturaE 3.2 (`.../2009/v3.2/Facturae`) signed, `etsi:` prefix, random numeric ids. |
| `xades_con_manifest.xsig` | detached-int root without CONTENT, `useManifest`: SignedInfo ref `Id="ManifestReference-..." Type="http://www.w3.org/2000/09/xmldsig#Manifest" URI="#Manifest-..."` + C14N; `ds:Object Id="ManifestObject-<uuid v3>"` with `ds:Manifest` of `urn:id:` references; two DataObjectFormat (one per manifest ref, no ObjectIdentifier, empty Encoding). |
| `ASIC-XAdES-2017789087353489524.zip` | ASiC-S: `mimetype` = `application/vnd.etsi.asic-s+zip`, `dataobject.bin`, `META-INF/signatures.xml` with root `asic:XAdESSignatures` (`xmlns:asic="http://uri.etsi.org/02918/v1.2.1#"`, `Id="asic:XAdESSignatures-Root-<uuid>"`); old manifest-based layout (manifest ref `URI="dataobject.bin"`). |
| `facturae_32v1.xml`, `factura_sinFirmar.xml`, `sample-facturae.xml` | unsigned FacturaE 3.2 / 3.1 inputs. |
| `SimpleXmlWithNamespace.xml`, `singlenodetbs.xml`, `xml_with_ids.xml`, `xpathnodenveloped.xml`, `xpathnodenvelopedwithns.xml`, `internally_detached_node_sibling.xml`, `sample-encoding-UTF-8.xml`, `sample-namespace-encoding-us-ascii.xml`, `sample-class-attributes.xml` | unsigned inputs for nodeToSign / XPath enveloped insertion / encodings / attribute named `class`. |
| `sample-internal-dtd.xml` | XML with internal DOCTYPE (rejected by the secure parser). |
| `book_style.xsl`, `style.xslt`, `external-style.xml`, `sample-embedded-style.xml`, `xmlwithremotestyle.xml` | XSLT stylesheet handling (`<?xml-stylesheet?>` embedded / external / remote). |
| `base64.b64`, `rubric.jpg`, `TEST_PDF_Certified.pdf`, `*.p12/.pfx/.jks` | data and test keystores. |

#### afirma-crypto-xmlsignature/src/test/resources
`sample-class-attributes.xml`, `sample-encoding-UTF-8.xml`, `xmlwithremotestyle.xml`, `base64.b64` (unsigned inputs) + keystores. No signed samples.

#### afirma-crypto-core-xml
No test resources.

#### afirma-crypto-validation/src/test/resources
`xades_epes_detached.xsig` - detached-int, XAdES-EPES (policy `urn:oid:2.16.724.1.3.1.1.2.1.9`, AGE policy),
rsa-sha512, base64 PDF content. (Other files are CAdES/PAdES.)

#### afirma-crypto-xadestri-client/src/test/resources

| File | Content |
|---|---|
| `firma-xades-detached.xml` | detached-int, base64 data ref with `Type=...#Object`. |
| `firma-xades-enveloped.xml` | enveloped on `<CATALOG>`. |
| `firma-xades-enveloping.xml`, `firma.xml`, `xades-5764226691627180206.xml`, `xades-7914107945663569970.xml` | enveloping, `ds:Object MimeType=application/pdf\|application/octet-stream Encoding=xmldsig#base64`. |
| `cofirma-xades-detached.xml`, `cofirma.xml` | 2 co-signatures; detached-int: both reference the same `#CONTENT-...`; enveloping cosign: root `AFIRMA` wrapping two enveloping `ds:Signature`s each with its own data Object. |
| `cofirma-xades-enveloped.xml` | 2 enveloped signatures as siblings under `<CATALOG>`. |
| `cofirma-xades-enveloping.xml` | root `AFIRMA` with 2 enveloping signatures (each its own `Object-...`). |
| `contrafirma-xades-{detached,enveloped,enveloping}.xml` | 4 signatures: 2 co-signatures, each with a nested `xades:CounterSignature` (ref `Type="http://uri.etsi.org/01903#CountersignedSignature"` to `#<sigId>-SignatureValue`, C14N transform). |
| `contrafirma-xades-detached-xl.xml` | XAdES-XL EPES with SignerRole + CounterSignature (both levels timestamped). |
| `firma_xades_manifest.xsig` | manifest signature (rsa-sha512). |
| `factura_sinFirmar.xml`, `xml_with_ids.xml` | unsigned inputs. |

---

### 12.2 Representative repository samples (trimmed)

**Caution:** these files were produced by older AutoFirma versions (2013-2022) and differ from the current code in details that matter for parity: KeyInfo child order (older: `KeyValue` before `X509Data`), the enveloped transform order (older: C14N, enveloped-signature, XPath; current: enveloped-signature, C14N, XPath), the `Type="...#Object"` attribute on enveloped/detached data references (current sign: none), the `xmlns` attribute order and empty-element rendering. Sections 3 and 13 (real current output) are normative.

Base64 values replaced by `...`. Indentation added for readability: **real AutoFirma output has no
whitespace text nodes inside `ds:Signature`** (single line); attribute order shown is not significant
(C14N sorts). Note `xades:QualifyingProperties` re-declares both `xmlns:ds` and `xmlns:xades`.

#### Sample 1 - XAdES-EPES "Detached" (internally detached, binary content) - `afirma-crypto-validation/src/test/resources/xades_epes_detached.xsig`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<AFIRMA Id="AFIRMA-Root-da0437d5-17bb-47ec-9f67-ec99f269caeb">
  <CONTENT Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="CONTENT-58d14e68-24a2-4c7b-882d-a538fc4144c3" MimeType="application/pdf">...</CONTENT>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
      <ds:Reference Id="Reference-0a4dab4b-c143-4841-9ff4-80b1f518d479" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#CONTENT-58d14e68-24a2-4c7b-882d-a538fc4144c3">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-KeyInfo">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-SignatureValue">...</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>...</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>...</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-QualifyingProperties" Target="#Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-Signature">
        <xades:SignedProperties Id="Signature-3f773af2-d31f-42d0-b725-f6d926420aa1-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2017-09-19T09:58:48+02:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>...</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=ACCVCA-120,OU=PKIACCV,O=ACCV,C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>9088758085625570612</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
            <xades:SignaturePolicyIdentifier>
              <xades:SignaturePolicyId>
                <xades:SigPolicyId>
                  <xades:Identifier>urn:oid:2.16.724.1.3.1.1.2.1.9</xades:Identifier>
                  <xades:Description></xades:Description>
                </xades:SigPolicyId>
                <xades:SigPolicyHash>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <ds:DigestValue>G7roucf600+f03r/o0bAOQ6WAs0=</ds:DigestValue>
                </xades:SigPolicyHash>
                <xades:SigPolicyQualifiers>
                  <xades:SigPolicyQualifier>
                    <xades:SPURI>https://sede.060.gob.es/politica_de_firma_anexo_1.pdf</xades:SPURI>
                  </xades:SigPolicyQualifier>
                </xades:SigPolicyQualifiers>
              </xades:SignaturePolicyId>
            </xades:SignaturePolicyIdentifier>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-0a4dab4b-c143-4841-9ff4-80b1f518d479">
              <xades:Description/>
              <xades:ObjectIdentifier>
                <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.1</xades:Identifier>
                <xades:Description/>
              </xades:ObjectIdentifier>
              <xades:MimeType>application/pdf</xades:MimeType>
              <xades:Encoding>http://www.w3.org/2000/09/xmldsig#base64</xades:Encoding>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</AFIRMA>
```
Detected profile: `XAdES B-Level` (EPES branch -> B-Level since SigningCertificate+SigningTime+DataObjectFormat/MimeType).

Id scheme visible here: `<sigId> = "Signature-" + UUID`; elements: `<sigId>-Signature`, `<sigId>-SignedProperties`,
`<sigId>-SignatureValue`, `<sigId>-KeyInfo`, `<sigId>-QualifyingProperties`; data reference
`Reference-<uuid>`; detached content `CONTENT-<uuid>`; root `AFIRMA-Root-<uuid>`; enveloping data object
`Object-<uuid>`; manifest `Manifest-<uuid>` / `ManifestReference-<uuid>` / `ManifestObject-<name-based uuid>`.

#### Sample 2 - XAdES Enveloped + countersignature (tree) - `afirma-crypto-xadestri-client/src/test/resources/contrafirma-xades-enveloped.xml` (first signature only)

The plain enveloped signature (`firma-xades-enveloped.xml`) is identical to the outer signature below
without `xades:UnsignedProperties`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CATALOG>
  <PLANT Id="1">...</PLANT>
  <!-- ...original document content, untouched... -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference Id="Reference-c8bf6963-33be-496f-b2c5-e64e9d9a8abb" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
            <ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">not(ancestor-or-self::ds:Signature)</ds:XPath>
          </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-KeyInfo">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-SignatureValue">...</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>...</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>...</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-QualifyingProperties" Target="#Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-Signature">
        <xades:SignedProperties Id="Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2016-01-19T11:14:18+01:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>...</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=ANF Assured ID CA1, SERIALNUMBER=G63287510, EMAILADDRESS=info@anf.es, OU=ANF Autoridad Intermedia de Identidad, O=ANF Autoridad de Certificacion, L=Barcelona (see current address at http://www.anf.es/es/address-direccion.html ), ST=Barcelona, C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>367703909322443328</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-c8bf6963-33be-496f-b2c5-e64e9d9a8abb">
              <xades:Description/>
              <xades:ObjectIdentifier>
                <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
                <xades:Description/>
              </xades:ObjectIdentifier>
              <xades:MimeType>text/xml</xades:MimeType>
              <xades:Encoding>UTF-8</xades:Encoding>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
        <xades:UnsignedProperties>
          <xades:UnsignedSignatureProperties>
            <xades:CounterSignature>
              <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-Signature">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                  <ds:Reference Id="Reference-14c9a5d1-c058-41bc-99ec-b214cdb6d109" Type="http://uri.etsi.org/01903#CountersignedSignature" URI="#Signature-f6a0cc31-b6a8-4f42-8fe2-c42706c1080d-SignatureValue">
                    <ds:Transforms>
                      <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                    <ds:DigestValue>...</ds:DigestValue>
                  </ds:Reference>
                  <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-SignedProperties">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                    <ds:DigestValue>...</ds:DigestValue>
                  </ds:Reference>
                  <ds:Reference URI="#Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-KeyInfo">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                    <ds:DigestValue>...</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue Id="Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-SignatureValue">...</ds:SignatureValue>
                <ds:KeyInfo Id="Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-KeyInfo">
                  <ds:X509Data>
                    <ds:X509Certificate>...</ds:X509Certificate>
                  </ds:X509Data>
                  <ds:KeyValue>
                    <ds:RSAKeyValue>
                      <ds:Modulus>...</ds:Modulus>
                      <ds:Exponent>AQAB</ds:Exponent>
                    </ds:RSAKeyValue>
                  </ds:KeyValue>
                </ds:KeyInfo>
                <ds:Object>
                  <xades:QualifyingProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-QualifyingProperties" Target="#Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-Signature">
                    <xades:SignedProperties Id="Signature-1ba92d6b-cd34-4dfd-8dee-046797b884bf-SignedProperties">
                      <xades:SignedSignatureProperties>
                        <xades:SigningTime>2016-01-19T11:17:05+01:00</xades:SigningTime>
                        <xades:SigningCertificate>
                          <xades:Cert>
                            <xades:CertDigest>
                              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                              <ds:DigestValue>...</ds:DigestValue>
                            </xades:CertDigest>
                            <xades:IssuerSerial>
                              <ds:X509IssuerName>CN=ANF Assured ID CA1, ...</ds:X509IssuerName>
                              <ds:X509SerialNumber>367703909322443328</ds:X509SerialNumber>
                            </xades:IssuerSerial>
                          </xades:Cert>
                        </xades:SigningCertificate>
                      </xades:SignedSignatureProperties>
                      <xades:SignedDataObjectProperties>
                        <xades:DataObjectFormat ObjectReference="#Reference-14c9a5d1-c058-41bc-99ec-b214cdb6d109">
                          <xades:Description/>
                          <xades:ObjectIdentifier>
                            <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
                            <xades:Description/>
                          </xades:ObjectIdentifier>
                          <xades:MimeType>text/xml</xades:MimeType>
                          <xades:Encoding>UTF-8</xades:Encoding>
                        </xades:DataObjectFormat>
                      </xades:SignedDataObjectProperties>
                    </xades:SignedProperties>
                  </xades:QualifyingProperties>
                </ds:Object>
              </ds:Signature>
            </xades:CounterSignature>
          </xades:UnsignedSignatureProperties>
        </xades:UnsignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
  <!-- second (co)signature Signature-f971e00c-... with its own CounterSignature follows as a sibling -->
</CATALOG>
```
Observations: co-signatures of an enveloped document are siblings under the document root, each with the
same `URI=""` + C14N + enveloped + XPath transforms; the countersignature references the parent's
`SignatureValue` Id with `Type="http://uri.etsi.org/01903#CountersignedSignature"` and an inclusive C14N
transform, and its DataObjectFormat points at that reference (MimeType `text/xml`, Encoding `UTF-8`, OID
`1.2.840.10003.5.109.10`).

#### Sample 3 - XAdES with Manifest (`useManifest=true`) - `afirma-crypto-xades/src/test/resources/xades_con_manifest.xsig` (fragment)

```xml
<AFIRMA Id="AFIRMA-Root-45505f56-9f65-4897-9e68-226caa1389ee">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-560f6a54-cfb4-42f2-ba84-0c8a7529e2d9-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
      <ds:Reference Id="ManifestReference-8bb89690-55a8-4af1-9b37-66c619e2cef0" Type="http://www.w3.org/2000/09/xmldsig#Manifest" URI="#Manifest-83a4d6c6-29e8-4e64-bc36-6ebc46b2e51b">
        <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
      <!-- SignedProperties and KeyInfo references as in Sample 1 -->
    </ds:SignedInfo>
    <!-- SignatureValue, KeyInfo (X509Data with 3 certificates = full chain, KeyValue) -->
    <ds:Object Id="ManifestObject-e5ab8925-3882-3204-b0c8-f36ea58383af">
      <ds:Manifest Id="Manifest-83a4d6c6-29e8-4e64-bc36-6ebc46b2e51b">
        <ds:Reference Id="Reference-405e5a25-6b01-4b94-be39-b2c87d5ad3f0" URI="urn:id:3086">
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <ds:DigestValue>4hrn/3Y9c/fn/uyq12w+D9A2aKc=</ds:DigestValue>
        </ds:Reference>
        <ds:Reference Id="Reference-032ef956-35b5-4c14-8917-3678ec20f411" URI="urn:id:3087">
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <ds:DigestValue>4hrn/3Y0c/fn/uyq12w+D9A2aKc=</ds:DigestValue>
        </ds:Reference>
      </ds:Manifest>
    </ds:Object>
    <ds:Object>
      <xades:QualifyingProperties ...>
        <xades:SignedProperties Id="Signature-560f6a54-...-SignedProperties">
          <!-- SigningTime, SigningCertificate -->
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-405e5a25-6b01-4b94-be39-b2c87d5ad3f0">
              <xades:Description/><xades:MimeType>plain/xml</xades:MimeType><xades:Encoding/>
            </xades:DataObjectFormat>
            <xades:DataObjectFormat ObjectReference="#Reference-032ef956-35b5-4c14-8917-3678ec20f411">
              <xades:Description/><xades:MimeType>image/jpg</xades:MimeType><xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</AFIRMA>
```
Note: in manifest mode the root `AFIRMA` has no `CONTENT` child; the DataObjectFormat entries point at the
manifest's internal references (one per external reference), with no ObjectIdentifier when none was given.

---

### 12.3 Parity checklist rows (validation / tri-phase / core)

| Feature | Java class / method | Notes |
|---|---|---|
| Validator dispatch by data type | `SignValiderFactory.getSignValider(byte[])` | PDF > FacturaE > XML > OOXML(null) > ODF(null) > binary |
| Validator by signer | `SignValiderFactory.getSignValider(AOSigner)` | XAdES & FacturaE -> XML; XMLDSig/ODF/OOXML -> null |
| XML validation (whole doc) | `ValidateXMLSignature.validate(byte[], boolean)` | all ds:Signature incl. nested; KO/NO_MATCH_DATA dedupe flag except per-reference; cert dates of all KeyInfo certs |
| Per-signature validation | `ValidateXMLSignature.validateSign(Element, String, boolean)` | externally detached -> UNKNOWN/CANT_VALIDATE_EXTERNALLY_DETACHED |
| Key selection | `ValidateXMLSignature.KeyValueKeySelector` | KeyValue first, else first X509Certificate |
| Same-document Id dereference fallback | `CustomUriDereferencer.dereference` / `getElementById` | attr name equalsIgnoreCase "Id"; http(s) URIs downloaded & parsed as XML |
| Long-term priority reorder | `SignValider.checkLongStandingValiditySign` | swap UNKNOWN/SIGN_PROFILE_NOT_CHECKED to index 0 when only CERTIFICATE_EXPIRED KOs |
| Result messages | `SignValidity.toString`, `validationmessages_*.properties` | keys `SignValidationMessage.0..27` |
| XAdES level per signature | `SignatureFormatDetectorXades.resolveSignerXAdESFormat` | only v1.3.2 ns; replicate LT bug and discarded noBaseline result |
| XAdES level per document | `SignatureFormatDetectorXades.getSignatureFormat` | excludes XMLTimeStamp sigs; B-Level checks only first signature |
| EPES check | `SignatureFormatDetectorXades.hasSignaturePolicyIdentifier` | public helper |
| Tri-phase client XAdES/FacturaE/ASiC | `AOXAdESTriPhaseSigner`, `AOFacturaETriPhaseSigner`, `AOXAdESASiCSTriPhaseSigner` | params op/cop/format/algo/cert/doc/params/session; `OK NEWID=` |
| Tri-phase session XML | `TriphaseData.parser/toString` | `<xml><firmas format><firma Id signid><param n>` |
| Client PKCS#1 over SignedInfo | `TriphaseDataSigner.doSign` | PRE -> PK1; delete PRE unless NEED_PRE |
| Server presign | `XAdESTriPhaseSignerServerSide.preSign` | dummy key, canonical SignedInfo, `====REPLACEME_i====` |
| Remove/insert common parts | `XAdESTriPhaseSignerUtil.removeCommonParts/insertCommonParts` | `====REPLACE-i====`; skipped for Enveloped/manifest |
| ECDSA raw signature for XMLDSig | `Pkcs1Utils.decodeSignature` | DER -> r\|\|s padded to max(len r,len s) (not curve size) |
| Format/mode constants | `AOSignConstants` | exact strings above |
| Digest name normalization | `AOSignConstants.getDigestAlgorithmName` | URI/OID/name -> SHA1/SHA-256/...; xmldsig-more#sha384 quirk |
| Signature alg composition | `AOSignConstants.composeSignatureAlgorithmName` | e.g. (SHA-256, EC) -> SHA256withECDSA |
| Signers tree | `AOTreeModel/AOTreeNode`, `Utils.getSimpleSignInfoNode` | root "Datos"; SigningTime parsed w/o offset; all descendant certs |
| MIME detection | `MimeHelper.getMimeType` | JMimeMagic + XML/Office refinement; null magic -> octet-stream |
| MIME -> OID | `MimeHelper.transformMimeTypeToOid`, `resources/mimetypes_oids.properties` | 16-entry table |
| Secure XML parsing | `SecureXmlBuilder`, `AOFileUtils.isXML` | DOCTYPE disallowed |
| Signed filename | `getSignedName` | `.xsig` / `.asics` |

---

## 13. Complete examples (XAdES family, real output)

All examples in this section are **real output** of the current Java code (HEAD, JDK 21, Santuario 3.0.5,
jxades 0.2.2), produced with the test certificate `EIDAS_CERTIFICADO_PRUEBAS___99999999R__1234.p12`
(RSA 2048, chain of 3) or `ciudadanohw_ecc_2023v1.p12` (EC P-256), algorithm `SHA256withRSA` /
`SHA256withECDSA`, data `hello world` (11 bytes) or the XML
`<?xml version="1.0" encoding="UTF-8"?>\n<doc xmlns="urn:test" z="1" b="2"><a Id="n1">1</a><!-- c --></doc>`,
and every one validated with a JSR-105 validator. Presentation rules:

* Indentation/line breaks were **added** for readability; the real output is a single line after the XML
  declaration (except whitespace that belongs to the user's own XML).
* Base64 longer than 40 characters is truncated to 10 characters + `…`.
* Attribute order is exactly the serialized one.

Useful fixed values: SHA-512("hello world") = `MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==`,
SHA-256("hello world") = `uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=`, Base64("hello world") = `aGVsbG8gd29ybGQ=`.

### 13.1 XAdES Enveloping, binary data, all defaults (EPES/advanced, SHA-512 references, full chain)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-Signature">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="Reference-2e6be15b-ce00-4f26-adb4-ca326d268059" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-96d882a8-3cd7-44bf-b38e-41010139671d">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>MJ7MSJwS1u…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-SignedProperties">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>9TGuljOTYf…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-KeyInfo">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>iayGf2j4od…</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-SignatureValue">RzBjrPHp6a…</ds:SignatureValue>
  <ds:KeyInfo Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-KeyInfo">
    <ds:X509Data>
      <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
      <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
      <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
    </ds:X509Data>
    <ds:KeyValue>
      <ds:RSAKeyValue>
        <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
        <ds:Exponent>AQAB</ds:Exponent>
      </ds:RSAKeyValue>
    </ds:KeyValue>
  </ds:KeyInfo>
  <ds:Object Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="Object-96d882a8-3cd7-44bf-b38e-41010139671d" MimeType="text/plain">aGVsbG8gd29ybGQ=</ds:Object>
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-QualifyingProperties" Target="#Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xades:SignedProperties Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-SignedProperties">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
          <xades:SigningCertificate>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerial>
                <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
              </xades:IssuerSerial>
            </xades:Cert>
          </xades:SigningCertificate>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#Reference-2e6be15b-ce00-4f26-adb4-ca326d268059">
            <xades:Description/>
            <xades:MimeType>text/plain</xades:MimeType>
            <xades:Encoding>http://www.w3.org/2000/09/xmldsig#base64</xades:Encoding>
          </xades:DataObjectFormat>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

Note: MIME `text/plain` was sniffed by `MimeHelper`; no `ObjectIdentifier` because `text/plain` has no OID mapping.

### 13.2 XAdES Enveloping, XML data

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-Signature">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="Reference-6ea01002-8060-46d0-9ba4-0ebc759f7124" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-f270d86f-856a-44ee-8669-268fc3bf9f97">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>Jzp42/o2Rt…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-SignedProperties">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>GtDa6tEsco…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-KeyInfo">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>6MN1amLOG4…</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-SignatureValue">WXFQo6Wx6n…</ds:SignatureValue>
  <ds:KeyInfo Id="Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-KeyInfo">
    <ds:X509Data>
      <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
      <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
      <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
    </ds:X509Data>
    <ds:KeyValue>
      <ds:RSAKeyValue>
        <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
        <ds:Exponent>AQAB</ds:Exponent>
      </ds:RSAKeyValue>
    </ds:KeyValue>
  </ds:KeyInfo>
  <ds:Object Id="Object-f270d86f-856a-44ee-8669-268fc3bf9f97" MimeType="text/xml">
    <doc xmlns="urn:test" b="2" z="1">
      <a Id="n1">1</a>
      <!-- c -->
    </doc>
  </ds:Object>
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-QualifyingProperties" Target="#Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xades:SignedProperties Id="Signature-f0a534a1-6821-40a1-a1a4-3eacb955f119-SignedProperties">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
          <xades:SigningCertificate>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerial>
                <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
              </xades:IssuerSerial>
            </xades:Cert>
          </xades:SigningCertificate>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#Reference-6ea01002-8060-46d0-9ba4-0ebc759f7124">
            <xades:Description/>
            <xades:ObjectIdentifier>
              <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
              <xades:Description/>
            </xades:ObjectIdentifier>
            <xades:MimeType>text/xml</xades:MimeType>
            <xades:Encoding/>
          </xades:DataObjectFormat>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

The user's attributes were re-ordered (`b` before `z`) and the comment is kept inside the Object (it is excluded from the digest by C14N without comments). The prolog/XML declaration of the input is gone.

### 13.3 XAdES Detached (internally detached), binary data (head only; rest as 13.1)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<AFIRMA Id="AFIRMA-Root-12e6ef00-4ae3-486f-b678-08f7d3ac2cca">
  <CONTENT Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="CONTENT-8bb81e36-3c74-4bd4-af0e-1d2c77239291" MimeType="text/plain">aGVsbG8gd29ybGQ=</CONTENT>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-16289dae-224a-4d69-ad1e-b2b50c362abc-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="Reference-d2045e2c-32de-4fd0-b39e-e8c88c29bb09" URI="#CONTENT-8bb81e36-3c74-4bd4-af0e-1d2c77239291">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>MJ7MSJwS1u…</ds:DigestValue>
      </ds:Reference>
   ...
```

No `Type` on the data reference (unlike Enveloping).

### 13.4 XAdES Detached, XML data

```xml
<?xml version="1.0" encoding="UTF-8"?>
<AFIRMA Id="AFIRMA-Root-ca793c1f-0273-4f68-b9a1-63f59bddad2a">
  <CONTENT Id="CONTENT-acb51ac9-d8f3-4a7d-b108-bf6ccd7fc108" MimeType="text/xml">
    <doc xmlns="urn:test" b="2" z="1">
      <a Id="n1">1</a>
      <!-- c -->
    </doc>
  </CONTENT>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="Reference-11b3694a-60fd-4742-a978-ccdcf20d1474" URI="#CONTENT-acb51ac9-d8f3-4a7d-b108-bf6ccd7fc108">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>X9isetm0Fj…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>QBy2r1wDTK…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-KeyInfo">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>70F6is7EOc…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-SignatureValue">OO+NfZDMVO…</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
        <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
        <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-QualifyingProperties" Target="#Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xades:SignedProperties Id="Signature-b7edb86e-0612-458f-8a5d-3c12ff6af7af-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-11b3694a-60fd-4742-a978-ccdcf20d1474">
              <xades:Description/>
              <xades:ObjectIdentifier>
                <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
                <xades:Description/>
              </xades:ObjectIdentifier>
              <xades:MimeType>text/xml</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</AFIRMA>
```

### 13.5 XAdES Enveloped (current transform order: enveloped, C14N, XPath)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<doc xmlns="urn:test" b="2" z="1">
  <a Id="n1">1</a>
  <!-- c -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-cf68e311-23f4-44b9-8009-bd21edda1663-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="Reference-67ca5e61-2114-4a06-8cde-dd21bf4aa2a9" URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
          <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
            <ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">not(ancestor-or-self::ds:Signature)</ds:XPath>
          </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>3D5BpEk5Fp…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-cf68e311-23f4-44b9-8009-bd21edda1663-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>Iv+s+welq8…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Signature-cf68e311-23f4-44b9-8009-bd21edda1663-KeyInfo">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>DevGUV41k8…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-cf68e311-23f4-44b9-8009-bd21edda1663-SignatureValue">MXhMHQnvwe…</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-cf68e311-23f4-44b9-8009-bd21edda1663-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
        <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
        <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-cf68e311-23f4-44b9-8009-bd21edda1663-QualifyingProperties" Target="#Signature-cf68e311-23f4-44b9-8009-bd21edda1663-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xades:SignedProperties Id="Signature-cf68e311-23f4-44b9-8009-bd21edda1663-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-67ca5e61-2114-4a06-8cde-dd21bf4aa2a9">
              <xades:Description/>
              <xades:ObjectIdentifier>
                <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
                <xades:Description/>
              </xades:ObjectIdentifier>
              <xades:MimeType>text/xml</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</doc>
```

Older samples in the repo (2013-2016) show C14N before enveloped-signature and `Type=...#Object` on the enveloped reference; current code produces the order above and no Type.

### 13.6 XAdES Externally Detached (`uri=https://example.org/doc.bin`, data = `hello world`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<AFIRMA Id="AFIRMA-Root-564bafa1-41fd-45da-a30b-953191e3f181">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="Reference-86089360-fdd6-4a80-87f8-8688f9aa137a" URI="https://example.org/doc.bin">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>aGVsbG8gd29ybGQ=</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>PTTTfDH5TL…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-KeyInfo">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>DHQyoB8LD0…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-SignatureValue">CqnobRwN7d…</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
        <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
        <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-QualifyingProperties" Target="#Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xades:SignedProperties Id="Signature-d11e784b-413c-49d2-b0c4-2c4a8b7a1e9f-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-86089360-fdd6-4a80-87f8-8688f9aa137a">
              <xades:Description/>
              <xades:MimeType>application/octet-stream</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</AFIRMA>
```

The DigestValue is literally Base64(`hello world`): the data bytes are taken as the precalculated digest (3.2.1 quirk), declared as SHA-512.

### 13.7 XAdES with Manifest (`useManifest=true`, `uri1=urn:id:1`, `md1`, `mimeType1=text/plain`, `uri2=https://example.org/2`, `md2`, `precalculatedHashAlgorithm=SHA-256`, data = null)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<AFIRMA Id="AFIRMA-Root-f4c8b5b3-48af-4dac-bf63-5f69b6e24398">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="ManifestReference-9c6606c0-ae66-4f00-addb-782e76555c8b" Type="http://www.w3.org/2000/09/xmldsig#Manifest" URI="#Manifest-16bbf251-9fe6-4da8-a480-6286d211c305">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>451SBGU397…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>aO/u3SLJeu…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-KeyInfo">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>34XD0bBw+5…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-SignatureValue">QCpbmeT2Qs…</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
        <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
        <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object Id="ManifestObject-0465a6da-9015-3b4b-ba87-537cdef112a5">
      <ds:Manifest Id="Manifest-16bbf251-9fe6-4da8-a480-6286d211c305">
        <ds:Reference Id="Reference-36d0de20-9679-4360-b21e-d09ca7d6a8ac" URI="urn:id:1">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>uU0nuZNNPg…</ds:DigestValue>
        </ds:Reference>
        <ds:Reference Id="Reference-d944884d-5ac2-45b2-9f21-92b13fd18d38" URI="https://example.org/2">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>uU0nuZNNPg…</ds:DigestValue>
        </ds:Reference>
      </ds:Manifest>
    </ds:Object>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-QualifyingProperties" Target="#Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xades:SignedProperties Id="Signature-6756ee6f-83f6-4f0f-ab7a-3f0ca8cad09a-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-36d0de20-9679-4360-b21e-d09ca7d6a8ac">
              <xades:Description/>
              <xades:MimeType>text/plain</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
            <xades:DataObjectFormat ObjectReference="#Reference-d944884d-5ac2-45b2-9f21-92b13fd18d38">
              <xades:Description/>
              <xades:MimeType>application/octet-stream</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</AFIRMA>
```

### 13.8 XAdES baseline (B-Level) with AGE policy, production place V2, claimed roles and one CTI

Params: `profile=baseline`, `policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9`, `policyIdentifierHash=G7roucf600+f03r/o0bAOQ6WAs0=`, `policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1`, `policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf`, `signatureProductionCity=Madrid`, `signatureProductionStreetAddress=Calle 1`, `signatureProductionProvince=Madrid`, `signatureProductionPostalCode=28001`, `signatureProductionCountry=ES`, `signerClaimedRoles=Firmante|Revisor`, `commitmentTypeIndications=1`, `commitmentTypeIndication0Identifier=1`, `commitmentTypeIndication0Description=desc`, `commitmentTypeIndication0DocumentationReferences=http://a.es/x|http://b.es/y`, `commitmentTypeIndication0CommitmentTypeQualifiers=Q1|Q2`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-95f43931-05ed-4015-ab1a-8d096d43aa3b-Signature">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="Reference-f44b7904-efd0-4865-9023-524067649789" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-f92cfa1f-8c9b-4039-8912-dab2c9f55a58">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>MJ7MSJwS1u…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-95f43931-05ed-4015-ab1a-8d096d43aa3b-SignedProperties">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>IyfMJXGQCv…</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="Signature-95f43931-05ed-4015-ab1a-8d096d43aa3b-SignatureValue">lWKu8Q6L8k…</ds:SignatureValue>
  <ds:KeyInfo Id="Signature-95f43931-05ed-4015-ab1a-8d096d43aa3b-KeyInfo">
    <ds:X509Data>
      <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
      <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
      <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
    </ds:X509Data>
    <ds:KeyValue>
      <ds:RSAKeyValue>
        <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
        <ds:Exponent>AQAB</ds:Exponent>
      </ds:RSAKeyValue>
    </ds:KeyValue>
  </ds:KeyInfo>
  <ds:Object Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="Object-f92cfa1f-8c9b-4039-8912-dab2c9f55a58" MimeType="text/plain">aGVsbG8gd29ybGQ=</ds:Object>
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-95f43931-05ed-4015-ab1a-8d096d43aa3b-QualifyingProperties" Target="#Signature-95f43931-05ed-4015-ab1a-8d096d43aa3b-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xades:SignedProperties Id="Signature-95f43931-05ed-4015-ab1a-8d096d43aa3b-SignedProperties">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
          <xades:SignaturePolicyIdentifier>
            <xades:SignaturePolicyId>
              <xades:SigPolicyId>
                <xades:Identifier>urn:oid:2.16.724.1.3.1.1.2.1.9</xades:Identifier>
                <xades:Description/>
              </xades:SigPolicyId>
              <xades:SigPolicyHash>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ds:DigestValue>G7roucf600+f03r/o0bAOQ6WAs0=</ds:DigestValue>
              </xades:SigPolicyHash>
              <xades:SigPolicyQualifiers>
                <xades:SigPolicyQualifier>
                  <xades:SPURI>https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf</xades:SPURI>
                </xades:SigPolicyQualifier>
              </xades:SigPolicyQualifiers>
            </xades:SignaturePolicyId>
          </xades:SignaturePolicyIdentifier>
          <xades:SigningCertificateV2>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerialV2/>
            </xades:Cert>
          </xades:SigningCertificateV2>
          <xades:SignatureProductionPlaceV2>
            <xades:City>Madrid</xades:City>
            <xades:StreetAddress>Calle 1</xades:StreetAddress>
            <xades:StateOrProvince>Madrid</xades:StateOrProvince>
            <xades:PostalCode>28001</xades:PostalCode>
            <xades:CountryName>ES</xades:CountryName>
          </xades:SignatureProductionPlaceV2>
          <xades:SignerRoleV2>
            <xades:ClaimedRoles>
              <xades:ClaimedRole>Firmante</xades:ClaimedRole>
              <xades:ClaimedRole>Revisor</xades:ClaimedRole>
            </xades:ClaimedRoles>
          </xades:SignerRoleV2>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#Reference-f44b7904-efd0-4865-9023-524067649789">
            <xades:Description/>
            <xades:MimeType>text/plain</xades:MimeType>
            <xades:Encoding>http://www.w3.org/2000/09/xmldsig#base64</xades:Encoding>
          </xades:DataObjectFormat>
          <xades:CommitmentTypeIndication>
            <xades:CommitmentTypeId>
              <xades:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin</xades:Identifier>
              <xades:Description>desc</xades:Description>
              <xades:DocumentationReferences>
                <xades:DocumentationReference>http://a.es/x</xades:DocumentationReference>
                <xades:DocumentationReference>http://b.es/y</xades:DocumentationReference>
              </xades:DocumentationReferences>
            </xades:CommitmentTypeId>
            <xades:ObjectReference>#Reference-f44b7904-efd0-4865-9023-524067649789</xades:ObjectReference>
            <xades:CommitmentTypeQualifiers>
              <xades:CommitmentTypeQualifier>Q1</xades:CommitmentTypeQualifier>
              <xades:CommitmentTypeQualifier>Q2</xades:CommitmentTypeQualifier>
            </xades:CommitmentTypeQualifiers>
          </xades:CommitmentTypeIndication>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

Note: no KeyInfo reference (baseline forces `keepKeyInfoUnsigned`), `SignaturePolicyIdentifier` precedes `SigningCertificateV2` (3.5.1), `IssuerSerialV2` empty.

### 13.9 XAdES EPES with every optional property and KeyInfo option

Params: same policy as 13.8 plus `policyDescription=Politica AGE`, same place/roles, `commitmentTypeIndications=1` with slot 0 = `1` and slot 1 = `5` (both emitted because indices 0..N are read), `addKeyInfoKeyName=true`, `addKeyInfoX509IssuerSerial=true`, `includeOnlySignningCertificate=true`, `keepKeyInfoUnsigned=true`, `contentTypeOid=1.2.3.4`, `mimeType=application/x-foo`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-86cc22e3-7610-4732-b6bf-06f7c173fd81-Signature">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="Reference-f4dc77e4-a040-4108-893d-58f9d0be10fd" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-1c74e02d-5df2-4471-b1bf-1d885237e14e">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>MJ7MSJwS1u…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-86cc22e3-7610-4732-b6bf-06f7c173fd81-SignedProperties">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>WuLMXB13RY…</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="Signature-86cc22e3-7610-4732-b6bf-06f7c173fd81-SignatureValue">coRUUGwi73…</ds:SignatureValue>
  <ds:KeyInfo Id="Signature-86cc22e3-7610-4732-b6bf-06f7c173fd81-KeyInfo">
    <ds:X509Data>
      <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
    </ds:X509Data>
    <ds:KeyValue>
      <ds:RSAKeyValue>
        <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
        <ds:Exponent>AQAB</ds:Exponent>
      </ds:RSAKeyValue>
    </ds:KeyValue>
    <ds:KeyName>CN=EIDAS CERTIFICADO PRUEBAS - 99999999R,SURNAME=EIDAS CERTIFICADO,GIVENNAME=PRUEBAS,SERIALNUMBER=IDCES-99999999R,C=ES</ds:KeyName>
    <ds:X509IssuerSerial>
      <ds:X509IssuerName>CN=AC FNMT Usuarios,OU=Ceres,O=FNMT-RCM,C=ES</ds:X509IssuerName>
      <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
    </ds:X509IssuerSerial>
  </ds:KeyInfo>
  <ds:Object Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="Object-1c74e02d-5df2-4471-b1bf-1d885237e14e" MimeType="application/x-foo">aGVsbG8gd29ybGQ=</ds:Object>
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-86cc22e3-7610-4732-b6bf-06f7c173fd81-QualifyingProperties" Target="#Signature-86cc22e3-7610-4732-b6bf-06f7c173fd81-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xades:SignedProperties Id="Signature-86cc22e3-7610-4732-b6bf-06f7c173fd81-SignedProperties">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
          <xades:SigningCertificate>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerial>
                <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
              </xades:IssuerSerial>
            </xades:Cert>
          </xades:SigningCertificate>
          <xades:SignaturePolicyIdentifier>
            <xades:SignaturePolicyId>
              <xades:SigPolicyId>
                <xades:Identifier>urn:oid:2.16.724.1.3.1.1.2.1.9</xades:Identifier>
                <xades:Description>Politica AGE</xades:Description>
              </xades:SigPolicyId>
              <xades:SigPolicyHash>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ds:DigestValue>G7roucf600+f03r/o0bAOQ6WAs0=</ds:DigestValue>
              </xades:SigPolicyHash>
              <xades:SigPolicyQualifiers>
                <xades:SigPolicyQualifier>
                  <xades:SPURI>https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf</xades:SPURI>
                </xades:SigPolicyQualifier>
              </xades:SigPolicyQualifiers>
            </xades:SignaturePolicyId>
          </xades:SignaturePolicyIdentifier>
          <xades:SignatureProductionPlace>
            <xades:City>Madrid</xades:City>
            <xades:StateOrProvince>Madrid</xades:StateOrProvince>
            <xades:PostalCode>28001</xades:PostalCode>
            <xades:CountryName>ES</xades:CountryName>
          </xades:SignatureProductionPlace>
          <xades:SignerRole>
            <xades:ClaimedRoles>
              <xades:ClaimedRole>Firmante</xades:ClaimedRole>
              <xades:ClaimedRole>Revisor</xades:ClaimedRole>
            </xades:ClaimedRoles>
          </xades:SignerRole>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#Reference-f4dc77e4-a040-4108-893d-58f9d0be10fd">
            <xades:Description/>
            <xades:ObjectIdentifier>
              <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.3.4</xades:Identifier>
              <xades:Description/>
            </xades:ObjectIdentifier>
            <xades:MimeType>application/x-foo</xades:MimeType>
            <xades:Encoding>http://www.w3.org/2000/09/xmldsig#base64</xades:Encoding>
          </xades:DataObjectFormat>
          <xades:CommitmentTypeIndication>
            <xades:CommitmentTypeId>
              <xades:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin</xades:Identifier>
              <xades:Description/>
            </xades:CommitmentTypeId>
            <xades:ObjectReference>#Reference-f4dc77e4-a040-4108-893d-58f9d0be10fd</xades:ObjectReference>
            <xades:CommitmentTypeQualifiers/>
          </xades:CommitmentTypeIndication>
          <xades:CommitmentTypeIndication>
            <xades:CommitmentTypeId>
              <xades:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfApproval</xades:Identifier>
              <xades:Description/>
            </xades:CommitmentTypeId>
            <xades:ObjectReference>#Reference-f4dc77e4-a040-4108-893d-58f9d0be10fd</xades:ObjectReference>
            <xades:CommitmentTypeQualifiers/>
          </xades:CommitmentTypeIndication>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

Note the two different DN renderings: `KeyName`/`X509IssuerSerial` (comma, no space; LDAP-escaped) vs `SigningCertificate/IssuerSerial` (comma + space; Java X500Name). `StreetAddress` is not emitted in EPES.

### 13.10 EC key (SHA256withECDSA) - KeyInfo has no KeyValue

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-1f293f01-69ef-40ef-bc81-9f207e3bb752-Signature">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
    <ds:Reference Id="Reference-b7f5747e-de8b-4f88-8a32-4ce84484cdd0" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-f4e6a409-d7e9-44ce-8ecb-4795c9d44ed0">
      <ds:Transforms>
   ...
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="Signature-1f293f01-69ef-40ef-bc81-9f207e3bb752-SignatureValue">KH5LUMJgLB…</ds:SignatureValue>
  <ds:KeyInfo Id="Signature-1f293f01-69ef-40ef-bc81-9f207e3bb752-KeyInfo">
    <ds:X509Data>
      <ds:X509Certificate>MIIF5DCCBU…</ds:X509Certificate>
      <ds:X509Certificate>MIIE5TCCBE…</ds:X509Certificate>
      <ds:X509Certificate>MIIC8TCCAl…</ds:X509Certificate>
    </ds:X509Data>
   ...
```

The issuer DN in `SigningCertificate` of this certificate renders as `CN=ACCV ECC1 CLIENTE, OID.2.5.4.97=VATES-A40573396, O=ISTEC, L=BURJASSOT, ST=VALENCIA, C=ES`. SignatureValue = 64 raw bytes (r||s).

### 13.11 Cosign of an Enveloped signature (second signature only)

```xml
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-2b60a6d2-b888-4090-84a0-202a66217e5e-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="Reference-738d1929-197e-4fe5-8842-9afcdb795a2a" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
          <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
            <ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">not(ancestor-or-self::ds:Signature)</ds:XPath>
          </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>3D5BpEk5Fp…</ds:DigestValue>
      </ds:Reference>
   ...
            <xades:DataObjectFormat ObjectReference="#Reference-738d1929-197e-4fe5-8842-9afcdb795a2a">
              <xades:Description/>
              <xades:ObjectIdentifier>
                <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
                <xades:Description/>
              </xades:ObjectIdentifier>
              <xades:MimeType>text/xml</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</doc>
```

The cosignature is appended as last child of the document root, copies the transforms of the first signature and adds `Type="http://www.w3.org/2000/09/xmldsig#Object"`.

### 13.12 Countersign (TREE) of the simple Enveloping signature 13.1

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-Signature">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="Reference-2e6be15b-ce00-4f26-adb4-ca326d268059" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object-96d882a8-3cd7-44bf-b38e-41010139671d">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>MJ7MSJwS1u…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-SignedProperties">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>9TGuljOTYf…</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-KeyInfo">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
      <ds:DigestValue>iayGf2j4od…</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-SignatureValue">RzBjrPHp6a…</ds:SignatureValue>
  <ds:KeyInfo Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-KeyInfo">
    <ds:X509Data>
      <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
      <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
      <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
    </ds:X509Data>
    <ds:KeyValue>
      <ds:RSAKeyValue>
        <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
        <ds:Exponent>AQAB</ds:Exponent>
      </ds:RSAKeyValue>
    </ds:KeyValue>
  </ds:KeyInfo>
  <ds:Object Encoding="http://www.w3.org/2000/09/xmldsig#base64" Id="Object-96d882a8-3cd7-44bf-b38e-41010139671d" MimeType="text/plain">aGVsbG8gd29ybGQ=</ds:Object>
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-QualifyingProperties" Target="#Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xades:SignedProperties Id="Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-SignedProperties">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
          <xades:SigningCertificate>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerial>
                <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
              </xades:IssuerSerial>
            </xades:Cert>
          </xades:SigningCertificate>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#Reference-2e6be15b-ce00-4f26-adb4-ca326d268059">
            <xades:Description/>
            <xades:MimeType>text/plain</xades:MimeType>
            <xades:Encoding>http://www.w3.org/2000/09/xmldsig#base64</xades:Encoding>
          </xades:DataObjectFormat>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
      <xades:UnsignedProperties>
        <xades:UnsignedSignatureProperties>
          <xades:CounterSignature>
            <ds:Signature Id="Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference Id="Reference-35814dcc-a8d5-4b96-8b87-5953ae823573" Type="http://uri.etsi.org/01903#CountersignedSignature" URI="#Signature-f5cbdb98-8631-4129-80da-c4992ce0de7c-SignatureValue">
                  <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                  </ds:Transforms>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>JqJP6jGmwB…</ds:DigestValue>
                </ds:Reference>
                <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-SignedProperties">
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>S/o9fWGAwA…</ds:DigestValue>
                </ds:Reference>
                <ds:Reference URI="#Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-KeyInfo">
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>rt1UBRAYxX…</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue Id="Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-SignatureValue">L6oyVNTvOv…</ds:SignatureValue>
              <ds:KeyInfo Id="Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-KeyInfo">
                <ds:X509Data>
                  <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
                  <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
                  <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
                </ds:X509Data>
                <ds:KeyValue>
                  <ds:RSAKeyValue>
                    <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
                    <ds:Exponent>AQAB</ds:Exponent>
                  </ds:RSAKeyValue>
                </ds:KeyValue>
              </ds:KeyInfo>
              <ds:Object>
                <xades:QualifyingProperties Id="Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-QualifyingProperties" Target="#Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
                  <xades:SignedProperties Id="Signature-72bffae2-4f1e-4874-a50c-411d3e2268e5-SignedProperties">
                    <xades:SignedSignatureProperties>
                      <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
                      <xades:SigningCertificate>
                        <xades:Cert>
                          <xades:CertDigest>
                            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                            <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
                          </xades:CertDigest>
                          <xades:IssuerSerial>
                            <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                            <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
                          </xades:IssuerSerial>
                        </xades:Cert>
                      </xades:SigningCertificate>
                    </xades:SignedSignatureProperties>
                    <xades:SignedDataObjectProperties>
                      <xades:DataObjectFormat ObjectReference="#Reference-35814dcc-a8d5-4b96-8b87-5953ae823573">
                        <xades:Description/>
                        <xades:ObjectIdentifier>
                          <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
                          <xades:Description/>
                        </xades:ObjectIdentifier>
                        <xades:MimeType>text/xml</xades:MimeType>
                        <xades:Encoding/>
                      </xades:DataObjectFormat>
                    </xades:SignedDataObjectProperties>
                  </xades:SignedProperties>
                </xades:QualifyingProperties>
              </ds:Object>
            </ds:Signature>
          </xades:CounterSignature>
        </xades:UnsignedSignatureProperties>
      </xades:UnsignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

`<xades:Encoding/>` is empty because the input root was the Signature (temporary `AFIRMA` wrapper document has no input encoding); with an Enveloped/Detached input it is `UTF-8`.

### 13.13 FacturaE (invoice body elided)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fe:Facturae xmlns:fe="http://www.facturae.es/Facturae/2009/v3.2/Facturae" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <FileHeader>…</FileHeader>
  <Parties>…</Parties>
  <Invoices>…</Invoices>
  <ds:Signature Id="Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="Reference-2e17ab3b-ba1c-4a4f-a43e-02eafc5f0572" URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>fsRtjdRvV8…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>oK4tpDp1yv…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-KeyInfo">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>RtU6Cp/q+H…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-SignatureValue">q+WjGuZIGs…</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
        <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
        <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-QualifyingProperties" Target="#Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xades:SignedProperties Id="Signature-4207f96f-e856-4006-bd59-82be86e2e6e2-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
            <xades:SignaturePolicyIdentifier>
              <xades:SignaturePolicyId>
                <xades:SigPolicyId>
                  <xades:Identifier>http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf</xades:Identifier>
                  <xades:Description/>
                </xades:SigPolicyId>
                <xades:SigPolicyHash>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <ds:DigestValue>Ohixl6upD6av8N7pEvDABhEL6hM=</ds:DigestValue>
                </xades:SigPolicyHash>
              </xades:SignaturePolicyId>
            </xades:SignaturePolicyIdentifier>
            <xades:SignerRole>
              <xades:ClaimedRoles>
                <xades:ClaimedRole>emisor</xades:ClaimedRole>
              </xades:ClaimedRoles>
            </xades:SignerRole>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-2e17ab3b-ba1c-4a4f-a43e-02eafc5f0572">
              <xades:Description/>
              <xades:ObjectIdentifier>
                <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>
                <xades:Description/>
              </xades:ObjectIdentifier>
              <xades:MimeType>text/xml</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</fe:Facturae>
```

Here the invoice root already declared `xmlns:ds`, so the serializer writes `Id` before `xmlns:ds` on `ds:Signature` (no new binding).

### 13.14 ASiC-S XAdES (`hello world`, no params)

Container (`unzip -lv`): all entries `Defl:N`; ZIP comment `mimetype=application/vnd.etsi.asic-s+zip`.

```text
  Length  Method  Name
      31  Defl:N  mimetype                    (application/vnd.etsi.asic-s+zip)
      11  Defl:N  dataobject.txt              (hello world)
   10622  Defl:N  META-INF/signatures.xml
```

`META-INF/signatures.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" Id="asic:XAdESSignatures-Root-4e5371a1-a5a8-4a36-afa0-5f1751aa7a2b">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-edde2311-0f86-4a82-8895-3b4ea445d8cf-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="Reference-e4e298fd-062d-4adc-b3dc-2a0670c9fbf2" URI="dataobject.txt">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>MJ7MSJwS1u…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature-edde2311-0f86-4a82-8895-3b4ea445d8cf-SignedProperties">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
        <ds:DigestValue>lgAJD3Sywv…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="Signature-edde2311-0f86-4a82-8895-3b4ea445d8cf-SignatureValue">tZshSuWdWL…</ds:SignatureValue>
    <ds:KeyInfo Id="Signature-edde2311-0f86-4a82-8895-3b4ea445d8cf-KeyInfo">
      <ds:X509Data>
        <ds:X509Certificate>MIIHhjCCBm…</ds:X509Certificate>
        <ds:X509Certificate>MIIG2jCCBM…</ds:X509Certificate>
        <ds:X509Certificate>MIIFgzCCA2…</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>ujAnB2L5X2…</ds:Modulus>
          <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
      <ds:KeyName>CN=EIDAS CERTIFICADO PRUEBAS - 99999999R,SURNAME=EIDAS CERTIFICADO,GIVENNAME=PRUEBAS,SERIALNUMBER=IDCES-99999999R,C=ES</ds:KeyName>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-edde2311-0f86-4a82-8895-3b4ea445d8cf-QualifyingProperties" Target="#Signature-edde2311-0f86-4a82-8895-3b4ea445d8cf-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xades:SignedProperties Id="Signature-edde2311-0f86-4a82-8895-3b4ea445d8cf-SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-10-16T13:39:15+02:00</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                  <ds:DigestValue>VmNYwDiCBB…</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES</ds:X509IssuerName>
                  <ds:X509SerialNumber>96891622000445695554354105786026700712</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#Reference-e4e298fd-062d-4adc-b3dc-2a0670c9fbf2">
              <xades:Description/>
              <xades:MimeType>application/octet-stream</xades:MimeType>
              <xades:Encoding/>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</asic:XAdESSignatures>
```

The Reference digest is SHA-512(`hello world`) computed by the ASiC signer and passed as data to the XAdES Externally Detached path.

### 13.15 XAdES-T fragment (reconstructed from code; no TSA was available)

```xml
<?xml version="1.0" encoding="UTF-8"?><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-U-Signature">
  ... SignedInfo / SignatureValue / KeyInfo / data Object exactly as 13.1 ...
  <ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="Signature-U-QualifyingProperties" Target="#Signature-U-Signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xades:SignedProperties Id="Signature-U-SignedProperties">...</xades:SignedProperties><xades:UnsignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
 <xades:UnsignedSignatureProperties>
  <xades:SignatureTimeStamp>
   <ds:CanonicalizationMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
   <xades:EncapsulatedTimeStamp>
MIAGCSqGSIb3DQEHAqCAMIACAQMx...(RFC 3161 TimeStampToken, Base64, one line)</xades:EncapsulatedTimeStamp>
  </xades:SignatureTimeStamp>
 </xades:UnsignedSignatureProperties>
</xades:UnsignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>
```

(The exact whitespace and the redundant `xmlns:xades` come from the literal in 3.10; the serializer may
order the `xmlns` attributes differently.)

---

## 14. Parity checklist

### 14.1 Shared XML infrastructure, XAdES, FacturaE, ASiC-S

| Feature | Java class / method | Notes |
|---|---|---|
| Algorithm name -> SignatureMethod URI | `XMLConstants.SIGN_ALGOS_URI` | RSA + ECDSA only, exact keys (2.3); XAdES rejects `MD*`; default `SHA512withRSA` |
| ECDSA signature value | Santuario | raw `r\|\|s` (P1363) |
| Base64 without line breaks | `XmlDSigProviderHelper.configureXmlDSigProvider`, afirma `Base64.encode`, jxades `Base64.encodeBytes` | everywhere |
| XML/non-XML classification | `AOFileUtils.isXML` + `SecureXmlBuilder` | DOCTYPE => binary (2.1) |
| Id lookup | `CustomUriDereferencer.getElementById` | attribute name `Id` case-insensitive, first in document order |
| Serialization | `Utils.writeXML` (LSSerializer, `namespaces=false`) | encoding from input/outputXmlEncoding; prolog lost; attributes sorted (2.2) |
| Custom transforms | `Utils.addCustomTransforms` | `xmlTransforms`, 0-based, XPath/XPath2/base64/enveloped, prepended |
| Cosign transform parsing | `Utils.getObjectReferenceTransforms` | XPath/XPath2 params only |
| Fallback dereferencer | `dereference.CustomUriDereferencer` | http(s) download + XML parse; `""`; `#id` |
| Stylesheets | `style.XmlStyle` (+ XAdES paths) | headless XAdES: effectively no-op, PI dropped |
| C14N engine | Santuario / XOM | inclusive 1.0 (subsets, namespace inheritance), exclusive, 1.1, comments variants |
| Param validation | `Utils.checkIllegalParams(..., xades=true)` | case-insensitive validate, case-sensitive dispatch |
| Default format / profile / digest / C14N | `XAdESSigner.sign` | Enveloping / advanced(EPES) / SHA-512 / inclusive |
| Binary embedding | `XAdESSigner.sign` | `CONTENT`/`ds:Object` Base64 text; `#base64` transform unless pre-encoded or `avoidBase64Transforms` |
| MIME / OID | `MimeHelper.getMimeType`, `transformMimeTypeToOid`, `createDataObjectFormat` | default-OID filtering on sign only |
| Wrapper root | `XAdESUtil.getRootElement` | `AFIRMA Id="AFIRMA-Root-<uuid>"`, `RootXmlNode*` params |
| Enveloping unwrap | `XAdESSigner.sign` | only if exactly one Signature |
| Detached `nodeToSign` | `XAdESSigner.sign` | sibling insertion / root moved under wrapper |
| Enveloped reference | `XAdESSigner.sign` | `""` or `#rootId`/`#nodeToSign`; enveloped, C14N, XPath; `facturaeSign`, `avoid*` flags |
| Enveloped insertion point | `XAdESUtil.getFirstElementFromXPath` | XPath, else nodeToSign element, else root; last child |
| Externally detached | `XAdESSigner.loadExternalReferenceData`, `createExternalReferenceFromUri` | **data used as digest**; null data => file/http dereference |
| Manifest | `XAdESUtil.createManifest`, `XAdESSigner.loadManifestReferencesData` | `uri<i>`/`md<i>` 1-based; `ManifestObject-<uuidV3>`; `ManifestReference-` |
| jxades factory | `XAdESUtil.newInstance` | EPES vs B_LEVEL; signing cert (V2 without IssuerSerialV2) |
| QualifyingProperties layout and order | jxades `QualifyingProperties`, `BasicXAdESImpl` / `BLevelXAdESImpl.marshalQualifyingProperties` | enum order => baseline policy before SigningCertificateV2 |
| SigningTime | jxades `SigningTime` + `ISO8601DateFormat` | always now, local zone, `+hh:mm` |
| SigningCertificate / V2 | jxades `SigningCertificate(V2)Details`, `SigningCertificate(V2)Impl` | hash/URI mismatch quirks; `IssuerSerialV2` empty |
| Issuer DN string | `X509Certificate.getIssuerDN().getName()` | Java `X500Name.toString()` rules (3.5.3) |
| Policy | `XAdESCommonMetadataUtil.getPolicy`, jxades `SignaturePolicyIdentifierImpl/Details` | OID -> `urn:oid:`; empty Description; download+SHA-1 if no hash |
| Production place / roles | `XAdESCommonMetadataUtil` + jxades details | V1 (EPES) vs V2 (baseline, + StreetAddress); claimed roles only |
| DataObjectFormat | jxades `DataObjectFormatDetails`, `ObjectIdentifierDetails` | Description + Encoding always; unprefixed `ObjectReference`/`Qualifier` |
| CommitmentTypeIndication | `XAdESUtil.parseCommitmentTypeIndications`, jxades `CommitmentTypeIndicationDetails` | indices 0..N; v1.2.2 URIs; qualifiers element always |
| KeyInfo | `AOXMLAdvancedSignature.newKeyInfo`, `EscapeHelper` | X509Data, KeyValue (not EC), KeyName, X509IssuerSerial (direct child) |
| Reference list / ids | `AOXMLAdvancedSignature.sign`, jxades `XMLAdvancedSignature` | data, style, SignedProperties, KeyInfo; `<sigId>-*` ids |
| PKCS#1 self-verification | `AOXMLAdvancedSignature.verifySignature` | default on; `validatePkcs1` internal |
| XAdES-T | `XAdESTspUtil.timestampXAdES` | 1.3.2 only; XOM C14N of SignatureValue in isolation; new UnsignedProperties |
| Multisign compatibility | `AOXAdESSigner.checkCompatibility`, `XAdESUtil.checkCompatibility` | single supported namespace; baseline = 2nd SSP child is SigningCertificateV2 |
| Profile forcing | `XAdESUtil.checkSignProfile` | `confirmDifferentProfile` must be a Boolean object |
| Archive timestamp guard | `XAdESUtil.checkArchiveSignatures` | `allowSignLTSignature` tri-state |
| Cosign | `XAdESCoSigner.cosign` | first signature's data refs; copies transforms; enveloping data copy; enveloped `Type=#Object`; appended to root |
| Enveloped cosign XPath check | `XAdESCoSigner.cosign` | `allowXadesEnvelopedWithoutXPath` tri-state |
| AGE policy vs enveloping cosign | `XAdESCoSigner.cosign`, `AdESPolicyPropertiesManager.isAgePolicyConfigurated` | `avoidAGEPolicyIncompatibilities` tri-state |
| Only-signing-cert multisign | jxades `XMLAdvancedSignature.sign(X509Certificate, ...)` | different KeyInfo, C14N fixed, KeyInfo always referenced |
| Countersign | `XAdESCounterSigner` (`countersignTree/Leafs/Nodes/Signers`, `cs`) | nested `xades:CounterSignature`; `Type=...#CountersignedSignature` except 1.1.1/1.2.2; DOF `text/xml` + input encoding |
| Signers tree | `AOXAdESSigner.getSignersStructure`, `generateSignsTree` | root `Datos`; skip `Timestamp` parents |
| isSign | `AOXAdESSigner.isSign`, `XAdESUtil.checkSignNodes` | every signature must contain a supported QualifyingProperties |
| Variant detection | `XAdESUtil.isSignatureElementEnveloped/ExternallyDetached/InternallyDetached/Enveloping`, `getSignatureDataReferenceList` | order matters; manifest => Enveloping |
| getData | `AOXAdESSigner.getData` | externally detached/manifest => null; first-child assumptions |
| needData | `XAdESUtil.isDataMandatory` | sign + (ext. detached or manifest) => optional |
| Signed name | `getSignedName` | `.xsig` / `.asics` |
| FacturaE params | `AOFacturaESigner.getFacturaEExtraParams` | whitelist; default role `emisor`; FacturaE 3.1 policy; null params => none |
| FacturaE detection | `AOFacturaESigner.isValidDataFile` | root `Facturae` + `FileHeader`/`Parties`/`Invoices` children |
| FacturaE multisign | `AOFacturaESigner.cosign/countersign` | unsupported |
| ASiC-S container | `ASiCUtil.createSContainer` | entry order, all DEFLATED, ZIP comment |
| ASiC-S sign | `AOXAdESASiCSSigner.sign`, `setASiCProperties` | hash passed as data; relative URI; `asic:XAdESSignatures` root; KeyName on, KeyInfo unsigned |
| ASiC-S cosign | `AOXAdESASiCSSigner.cosign`, `UriAndDataDereferencer` | map URI -> data bytes |
| Error codes | `XMLErrorCode`, `XAdESErrorCode` | 3.15 |

### 14.2 XMLdSig

See the table at the end of section 6 ("Parity checklist").

### 14.3 ODF / OOXML

See the table at the end of section 8 ("Parity checklist rows (ODF / OOXML)").

### 14.4 Validation / tri-phase / core

See the table at the end of section 12 ("Parity checklist rows (validation / tri-phase / core)").

---

## 15. Gotchas summary (decide "replicate" vs "fix" explicitly)

1. **Externally Detached XAdES uses the `data` bytes as the DigestValue** whenever data is non-null
   (`precalculatedHashAlgorithm` defaults to `referencesDigestMethod`, so the "precalculated" path is
   always taken). ASiC relies on it.
2. **jxades element order**: B-Level with a policy writes `SignaturePolicyIdentifier` before
   `SigningCertificateV2`; this also defeats AutoFirma's own baseline detection (2nd-child heuristic), so
   co/countersignatures of such signatures fall back to the advanced profile.
3. **CertDigest hash vs URI**: SigningCertificate computes SHA-1 for any URI other than sha256/sha512;
   SigningCertificateV2 computes SHA-256 for anything but sha512 - the declared URI can lie.
4. **SigningTime** is always "now" in the JVM local zone (`yyyy-MM-ddTHH:mm:ss+hh:mm`), never configurable.
5. **DN strings** differ by place: SigningCertificate uses Java `X500Name.toString()` (`", "`), KeyInfo
   KeyName/X509IssuerSerial use a doubly-applied LDAP escaping (`","` + `\C3\A1`-style escapes), jxades'
   cosign KeyInfo uses RFC 1779 (`OID.2.5.4.4=`), ODF uses RFC 2253 (`2.5.4.4=#0c11...`).
6. **CommitmentTypeIndications**: indices `0..N` inclusive are read for `commitmentTypeIndications=N`.
7. **format/mode** are validated case-insensitively but dispatched case-sensitively (XAdES and XMLdSig):
   a differently cased format signs no data.
8. **Profile/multisign**: cosign/countersign ignore the requested `profile` and copy the existing one;
   `confirmDifferentProfile` only works as a `java.lang.Boolean` object; baseline does not force
   `keepKeyInfoUnsigned` in cosign/countersign (it does in sign).
9. **Enveloped cosign** adds `Type="...#Object"` to the data reference and appends the new signature as last
   child of the root even if the first signature was placed elsewhere (XPath/nodeToSign).
10. **Enveloping cosign** duplicates the data inside each new signature (`Object-<uuid>` copy) and wraps the
    document in `<AFIRMA Id="AfirmaRoot-<uuid>">` (different Id format from sign's `AFIRMA-Root-<uuid>`).
11. **Countersign DataObjectFormat Encoding** = parser-detected input encoding, empty when the input root
    was the Signature.
12. **XAdES-T**: only for the 1.3.2 namespace, only the first signature of the document, imprint = XOM
    C14N of `ds:SignatureValue` without inherited namespaces, always a new `UnsignedProperties`.
13. **Stylesheets**: XAdES effectively never signs them (headless + `allowExternal=false`) and Enveloped
    output loses the `<?xml-stylesheet?>` PI and the whole prolog/DOCTYPE; XMLdSig's remote-stylesheet
    enveloped case yields an invalid signature.
14. **DOCTYPE** anywhere in the input makes it "not XML" (binary embedding, Enveloped rejected).
15. **Attribute re-ordering** of user XML and loss of prolog/epilog content in all wrapped/enveloped
    outputs (cosmetic; signatures are computed after these changes).
16. **`getData` heuristics**: first child of root = CONTENT; first `ds:Object` = data; only direct-child
    signatures removed for enveloped; pre-encoded Base64 returns the Base64 text (XAdES) or decoded bytes
    (XMLdSig).
17. **Manifest signatures** are reported as Enveloping by `getSignInfo` and return `null` data.
18. **FacturaE** with `null` extraParams gets no policy and no signer role; the caller's Properties are
    mutated; only a whitelist of params survives (digest SHA-512, EPES).
19. **ASiC-S** writes `mimetype` DEFLATED (spec requires STORED) and uses a root Id containing a colon.
20. **`includeOnlySignningCertificate` in cosign/countersign** switches to jxades' KeyInfo builder
    (KeyValue first + X509SubjectName + X509IssuerSerial) and ignores KeyInfo/C14N options.
21. **Canonicalization `none`** only works in sign; cosign/countersign fail with it.
22. **SHA-384** works as `referencesDigestMethod` URI for references but not for precalculated/policy hashes
    (`getDigestMethodByCommonName` only knows SHA1/256/512) and maps CertDigest to SHA-1/SHA-256.
23. **XMLdSig specifics** (section 6): KeyInfo reference reuses the data transforms; externally detached
    uses `URI=""`; default reference digest SHA-1; countersignatures are siblings.
24. **ODF** ignores the signature algorithm (always rsa-sha1), canonicalizes only the 4 root XML parts,
    `dc:date` without zone; **OOXML** hard-codes SHA-512/SHA-256, needs AWT screen info, uses a 12-hour
    clock with a fake `Z`, does not sign `ppt/` parts, and requires the custom RelationshipTransform.
25. **Validation** (section 9) only checks crypto + certificate dates, recognizes only XAdES 1.3.2 for level
    detection and has known detection bugs to replicate.
