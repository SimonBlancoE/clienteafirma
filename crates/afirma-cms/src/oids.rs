//! Identificadores de objeto usados en CMS, CAdES y RFC 3161.

/// `id-data`.
pub const DATA: &str = "1.2.840.113549.1.7.1";
/// `id-signedData`.
pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// `id-envelopedData`.
pub const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
/// `id-signedAndEnvelopedData`.
pub const SIGNED_AND_ENVELOPED_DATA: &str = "1.2.840.113549.1.7.4";
/// `id-digestedData`.
pub const DIGESTED_DATA: &str = "1.2.840.113549.1.7.5";
/// `id-encryptedData`.
pub const ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
/// `id-ct-TSTInfo`.
pub const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// Atributo `contentType`.
pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
/// Atributo `messageDigest`.
pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// Atributo `signingTime`.
pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
/// Atributo `counterSignature`.
pub const COUNTER_SIGNATURE: &str = "1.2.840.113549.1.9.6";
/// `id-aa-contentHint`.
pub const CONTENT_HINT: &str = "1.2.840.113549.1.9.16.2.4";
/// `id-aa-signingCertificate`.
pub const SIGNING_CERTIFICATE: &str = "1.2.840.113549.1.9.16.2.12";
/// `id-aa-signatureTimeStampToken`.
pub const SIGNATURE_TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
/// `id-aa-ets-sigPolicyId`.
pub const SIG_POLICY_ID: &str = "1.2.840.113549.1.9.16.2.15";
/// `id-aa-ets-commitmentType`.
pub const COMMITMENT_TYPE: &str = "1.2.840.113549.1.9.16.2.16";
/// `id-aa-ets-signerLocation`.
pub const SIGNER_LOCATION: &str = "1.2.840.113549.1.9.16.2.17";
/// `id-aa-ets-signerAttr`.
pub const SIGNER_ATTR: &str = "1.2.840.113549.1.9.16.2.18";
/// `id-aa-ets-otherSigCert`.
pub const OTHER_SIG_CERT: &str = "1.2.840.113549.1.9.16.2.19";
/// `id-aa-ets-certificateRefs`.
pub const CERTIFICATE_REFS: &str = "1.2.840.113549.1.9.16.2.21";
/// `id-aa-ets-revocationRefs`.
pub const REVOCATION_REFS: &str = "1.2.840.113549.1.9.16.2.22";
/// `id-aa-ets-certValues`.
pub const CERT_VALUES: &str = "1.2.840.113549.1.9.16.2.23";
/// `id-aa-ets-revocationValues`.
pub const REVOCATION_VALUES: &str = "1.2.840.113549.1.9.16.2.24";
/// `id-aa-ets-escTimeStamp`.
pub const ESC_TIMESTAMP: &str = "1.2.840.113549.1.9.16.2.25";
/// `id-aa-ets-certCRLTimestamp`.
pub const CERT_CRL_TIMESTAMP: &str = "1.2.840.113549.1.9.16.2.26";
/// `id-aa-ets-archiveTimestamp`.
pub const ARCHIVE_TIMESTAMP: &str = "1.2.840.113549.1.9.16.2.27";
/// `id-aa-ets-attrCertificateRefs`.
pub const ATTR_CERTIFICATE_REFS: &str = "1.2.840.113549.1.9.16.2.44";
/// `id-aa-ets-attrRevocationRefs`.
pub const ATTR_REVOCATION_REFS: &str = "1.2.840.113549.1.9.16.2.45";
/// `id-aa-signingCertificateV2`.
pub const SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
/// `id-aa-ets-archiveTimestampV2`.
pub const ARCHIVE_TIMESTAMP_V2: &str = "1.2.840.113549.1.9.16.2.48";
/// `id-spq-ets-uri`.
pub const SPQ_ETS_URI: &str = "1.2.840.113549.1.9.16.5.1";
/// Prefijo de `id-cti-ets-proofOf*` (se añade `.1` a `.6`).
pub const COMMITMENT_TYPE_PREFIX: &str = "1.2.840.113549.1.9.16.6";
/// `id-aa-ets-mimeType`.
pub const MIME_TYPE: &str = "0.4.0.1733.2.1";
/// `long-term-validation`.
pub const LONG_TERM_VALIDATION: &str = "0.4.0.1733.2.2";
/// `id-aa-ets-archiveTimestampV3`.
pub const ARCHIVE_TIMESTAMP_V3: &str = "0.4.0.1733.2.4";
/// `id-aa-ets-signerAttrV2`.
pub const SIGNER_ATTR_V2: &str = "0.4.0.19122.1.1";
/// `id-at-role`.
pub const ROLE: &str = "2.5.4.72";
/// `id-at-serialNumber` (atributo no estándar de las firmas CMS de AutoFirma).
pub const SERIAL_NUMBER: &str = "2.5.4.5";
/// Extensión `certificatePolicies`.
pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";
/// Política por defecto de las peticiones de sello de tiempo.
pub const DEFAULT_TSA_POLICY: &str = "0.4.0.2023.1.1";

/// `rsaEncryption`.
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// `id-ecPublicKey`.
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `id-dsa`.
pub const DSA: &str = "1.2.840.10040.4.1";
/// Curva P-256.
pub const CURVE_P256: &str = "1.2.840.10045.3.1.7";
/// Curva P-384.
pub const CURVE_P384: &str = "1.3.132.0.34";
/// Curva P-521.
pub const CURVE_P521: &str = "1.3.132.0.35";
