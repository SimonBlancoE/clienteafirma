//! Constantes de AutoFirma (`AOSignConstants`, `CounterSignTarget`,
//! `MimeHelper`, `ASiCUtil`, `ExtraParamsProcessor`, `LogManager`...), con
//! sus valores exactos de la versión Java 1.9.1 (`docs/spec/07-core.md` §1).
//!
//! La tabla de formatos registrados en `AOSignerFactory` está en
//! [`crate::formats`].

// ---------------------------------------------------------------------------
// §1.1 Nombres de formato de firma
// ---------------------------------------------------------------------------

/// Selección automática del formato. Se compara siempre sin distinguir
/// mayúsculas. No está registrado en `AOSignerFactory`.
pub const SIGN_FORMAT_AUTO: &str = "auto";
/// CMS/PKCS#7.
pub const SIGN_FORMAT_CMS: &str = "CMS/PKCS#7";
/// CAdES en contenedor ASiC-S.
pub const SIGN_FORMAT_CADES_ASIC_S: &str = "CAdES-ASiC-S";
/// CAdES en contenedor ASiC-S trifásica.
pub const SIGN_FORMAT_CADES_ASIC_S_TRI: &str = "CAdES-ASiC-S-tri";
/// CAdES.
pub const SIGN_FORMAT_CADES: &str = "CAdES";
/// CAdES trifásica (sin guion).
pub const SIGN_FORMAT_CADES_TRI: &str = "CAdEStri";
/// PKCS#1 sin formato (`NONE`).
pub const SIGN_FORMAT_PKCS1: &str = "NONE";
/// Nombre alternativo de PKCS#1 (no registrado en la factoría).
pub const SIGN_FORMAT_PKCS1_ALT1: &str = "PKCS1";
/// Nombre alternativo de PKCS#1 (no registrado en la factoría).
pub const SIGN_FORMAT_PKCS1_ALT2: &str = "PKCS#1";
/// PKCS#1 trifásica.
pub const SIGN_FORMAT_PKCS1_TRI: &str = "NONEtri";
/// XAdES en contenedor ASiC-S.
pub const SIGN_FORMAT_XADES_ASIC_S: &str = "XAdES-ASiC-S";
/// XAdES en contenedor ASiC-S trifásica.
pub const SIGN_FORMAT_XADES_ASIC_S_TRI: &str = "XAdES-ASiC-S-tri";
/// XAdES Detached (también es un valor del parámetro `format` de XAdES).
pub const SIGN_FORMAT_XADES_DETACHED: &str = "XAdES Detached";
/// XAdES Externally Detached (no registrado en la factoría).
pub const SIGN_FORMAT_XADES_EXTERNALLY_DETACHED: &str = "XAdES Externally Detached";
/// XAdES Enveloped.
pub const SIGN_FORMAT_XADES_ENVELOPED: &str = "XAdES Enveloped";
/// XAdES Enveloping.
pub const SIGN_FORMAT_XADES_ENVELOPING: &str = "XAdES Enveloping";
/// XAdES.
pub const SIGN_FORMAT_XADES: &str = "XAdES";
/// XAdES trifásica.
pub const SIGN_FORMAT_XADES_TRI: &str = "XAdEStri";
/// XMLDSig Detached.
pub const SIGN_FORMAT_XMLDSIG_DETACHED: &str = "XMLDSig Detached";
/// XMLDSig Externally Detached (no registrado en la factoría).
pub const SIGN_FORMAT_XMLDSIG_EXTERNALLY_DETACHED: &str = "XMLDSig Externally Detached";
/// XMLDSig Enveloped.
pub const SIGN_FORMAT_XMLDSIG_ENVELOPED: &str = "XMLDSig Enveloped";
/// XMLDSig Enveloping.
pub const SIGN_FORMAT_XMLDSIG_ENVELOPING: &str = "XMLDSig Enveloping";
/// XMLDSig.
pub const SIGN_FORMAT_XMLDSIG: &str = "XMLDSig";
/// OOXML.
pub const SIGN_FORMAT_OOXML: &str = "OOXML (Office Open XML)";
/// Nombre alternativo de OOXML.
pub const SIGN_FORMAT_OOXML_ALT1: &str = "OOXML";
/// ODF.
pub const SIGN_FORMAT_ODF: &str = "ODF (Open Document Format)";
/// Nombre alternativo de ODF.
pub const SIGN_FORMAT_ODF_ALT1: &str = "ODF";
/// Firma PDF (nombre con el que `AOSignerFactory.getSignFormat` identifica
/// al firmador PDF).
pub const SIGN_FORMAT_PDF: &str = "Adobe PDF";
/// Firma PDF trifásica.
pub const SIGN_FORMAT_PDF_TRI: &str = "Adobe PDF TriPhase";
/// PAdES.
pub const SIGN_FORMAT_PADES: &str = "PAdES";
/// PAdES trifásica (el valor real es `PAdEStri`).
pub const SIGN_FORMAT_PADES_TRI: &str = "PAdEStri";
/// SOAP (constante sin uso, no registrada en la factoría).
pub const SIGN_FORMAT_SOAP: &str = "SOAP";
/// FacturaE.
pub const SIGN_FORMAT_FACTURAE: &str = "FacturaE";
/// FacturaE trifásica.
pub const SIGN_FORMAT_FACTURAE_TRI: &str = "FacturaEtri";
/// Nombre alternativo de FacturaE.
pub const SIGN_FORMAT_FACTURAE_ALT1: &str = "Factura-e";
/// Formato de firma por defecto.
pub const DEFAULT_SIGN_FORMAT: &str = SIGN_FORMAT_CADES;

// ---------------------------------------------------------------------------
// §1.2 Operaciones masivas, perfiles y modos
// ---------------------------------------------------------------------------

/// Operación masiva de firma.
pub const MASSIVE_OPERATION_SIGN: &str = "FIRMAR";
/// Operación masiva de cofirma.
pub const MASSIVE_OPERATION_COSIGN: &str = "COFIRMAR";
/// Operación masiva de contrafirma de todo el árbol.
pub const MASSIVE_OPERATION_COUNTERSIGN_TREE: &str = "CONTRAFIRMAR_ARBOL";
/// Operación masiva de contrafirma de las hojas.
pub const MASSIVE_OPERATION_COUNTERSIGN_LEAFS: &str = "CONTRAFIRMAR_HOJAS";
/// Operación masiva por defecto.
pub const DEFAULT_MASSIVE_OPERATION: &str = MASSIVE_OPERATION_SIGN;
/// Perfil de firma avanzado.
pub const SIGN_PROFILE_ADVANCED: &str = "advanced";
/// Perfil de firma baseline.
pub const SIGN_PROFILE_BASELINE: &str = "baseline";
/// Perfil de firma por defecto.
pub const DEFAULT_SIGN_PROFILE: &str = SIGN_PROFILE_ADVANCED;
/// Modo explícito: la firma no incluye los datos.
pub const SIGN_MODE_EXPLICIT: &str = "explicit";
/// Modo implícito: la firma incluye los datos.
pub const SIGN_MODE_IMPLICIT: &str = "implicit";
/// Modo de firma por defecto.
pub const DEFAULT_SIGN_MODE: &str = SIGN_MODE_EXPLICIT;

// ---------------------------------------------------------------------------
// §1.3 Tipos de contenido CMS, OID y subfiltros PDF
// ---------------------------------------------------------------------------

/// Tipo de contenido CMS `Data`.
pub const CMS_CONTENTTYPE_DATA: &str = "Data";
/// Tipo de contenido CMS `SignedData`.
pub const CMS_CONTENTTYPE_SIGNEDDATA: &str = "SignedData";
/// Tipo de contenido CMS `DigestedData`.
pub const CMS_CONTENTTYPE_DIGESTEDDATA: &str = "DigestedData";
/// Tipo de contenido CMS `CompressedData`.
pub const CMS_CONTENTTYPE_COMPRESSEDDATA: &str = "CompressedData";
/// Tipo de contenido CMS `EncryptedData`.
pub const CMS_CONTENTTYPE_ENCRYPTEDDATA: &str = "EncryptedData";
/// Tipo de contenido CMS `EnvelopedData`.
pub const CMS_CONTENTTYPE_ENVELOPEDDATA: &str = "EnvelopedData";
/// Tipo de contenido CMS `SignedAndEnvelopedData`.
pub const CMS_CONTENTTYPE_SIGNEDANDENVELOPEDDATA: &str = "SignedAndEnvelopedData";
/// Tipo de contenido CMS `AuthenticatedData`.
pub const CMS_CONTENTTYPE_AUTHENTICATEDDATA: &str = "AuthenticatedData";
/// Tipo de contenido CMS `AuthEnvelopedData`.
pub const CMS_CONTENTTYPE_AUTHENVELOPEDDATA: &str = "AuthEnvelopedData";
/// Tipo de contenido CMS por defecto.
pub const DEFAULT_CMS_CONTENTTYPE: &str = CMS_CONTENTTYPE_ENVELOPEDDATA;
/// OID por defecto de los datos a firmar (sintaxis LDAP "Octet String").
pub const DEFAULT_OID_TO_SIGN: &str = "1.3.6.1.4.1.1466.115.121.1.40";
/// Subfiltro PDF básico (PKCS#7).
pub const PADES_SUBFILTER_BASIC: &str = "adbe.pkcs7.detached";
/// Subfiltro PDF PAdES (CAdES).
pub const PADES_SUBFILTER_BES: &str = "ETSI.CAdES.detached";

// ---------------------------------------------------------------------------
// §1.4 Algoritmos
// ---------------------------------------------------------------------------

/// Huella SHA-1.
pub const DIGEST_ALGORITHM_SHA1: &str = "SHA1";
/// Huella SHA-256.
pub const DIGEST_ALGORITHM_SHA256: &str = "SHA256";
/// Huella SHA-384.
pub const DIGEST_ALGORITHM_SHA384: &str = "SHA384";
/// Huella SHA-512.
pub const DIGEST_ALGORITHM_SHA512: &str = "SHA512";
/// Firma SHA1withRSA.
pub const SIGN_ALGORITHM_SHA1WITHRSA: &str = "SHA1withRSA";
/// Firma SHA256withRSA.
pub const SIGN_ALGORITHM_SHA256WITHRSA: &str = "SHA256withRSA";
/// Firma SHA384withRSA.
pub const SIGN_ALGORITHM_SHA384WITHRSA: &str = "SHA384withRSA";
/// Firma SHA512withRSA.
pub const SIGN_ALGORITHM_SHA512WITHRSA: &str = "SHA512withRSA";
/// Firma RSA sin huella.
pub const SIGN_ALGORITHM_NONEWITHRSA: &str = "NONEwithRSA";
/// Firma SHA1withDSA.
pub const SIGN_ALGORITHM_SHA1WITHDSA: &str = "SHA1withDSA";
/// Firma SHA1withECDSA.
pub const SIGN_ALGORITHM_SHA1WITHECDSA: &str = "SHA1withECDSA";
/// Firma SHA224withECDSA.
pub const SIGN_ALGORITHM_SHA224WITHECDSA: &str = "SHA224withECDSA";
/// Firma SHA256withECDSA.
pub const SIGN_ALGORITHM_SHA256WITHECDSA: &str = "SHA256withECDSA";
/// Firma SHA384withECDSA.
pub const SIGN_ALGORITHM_SHA384WITHECDSA: &str = "SHA384withECDSA";
/// Firma SHA512withECDSA.
pub const SIGN_ALGORITHM_SHA512WITHECDSA: &str = "SHA512withECDSA";
/// Firma ECDSA sin huella.
pub const SIGN_ALGORITHM_NONEWITHECDSA: &str = "NONEwithECDSA";
/// Algoritmo de firma por defecto.
pub const DEFAULT_SIGN_ALGO: &str = SIGN_ALGORITHM_SHA512WITHRSA;

// ---------------------------------------------------------------------------
// §1.5 Objetivos de contrafirma (`CounterSignTarget.toString()`)
// ---------------------------------------------------------------------------

/// Contrafirma de los firmantes indicados por su Common Name.
pub const COUNTERSIGN_TARGET_SIGNERS: &str = "signers";
/// Contrafirma de los nodos indicados por su índice en preorden.
pub const COUNTERSIGN_TARGET_NODES: &str = "nodes";
/// Contrafirma de todos los nodos del árbol.
pub const COUNTERSIGN_TARGET_TREE: &str = "tree";
/// Contrafirma de las hojas del árbol.
pub const COUNTERSIGN_TARGET_LEAFS: &str = "leafs";

// ---------------------------------------------------------------------------
// §1.6 Otras constantes del núcleo
// ---------------------------------------------------------------------------

/// Valor "desconocido" de JMimeMagic.
pub const UNKNOWN_JMIMEMAGIC_VALUE: &str = "???";
/// Tipo MIME por defecto (`MimeHelper.DEFAULT_MIMETYPE`).
pub const DEFAULT_MIMETYPE: &str = "application/octet-stream";
/// Tipo MIME por defecto de `OfficeAnalizer` (**con la errata del original**).
pub const OFFICE_ANALIZER_DEFAULT_MIMETYPE: &str = "application/octect-stream";
/// Descripción por defecto del contenido.
pub const DEFAULT_CONTENT_DESCRIPTION: &str = "binary";
/// OID por defecto del tipo de contenido (id-data).
pub const DEFAULT_CONTENT_OID_DATA: &str = "1.2.840.113549.1.7.1";
/// Tamaño máximo (decimal, 1 GB) que analizan `OfficeAnalizer` y `ASiCUtil`.
pub const THRESHOLD_FILE_SIZE: usize = 1_000_000_000;
/// Tipo MIME de los contenedores ASiC-S.
pub const ASIC_S_MIMETYPE: &str = "application/vnd.etsi.asic-s+zip";
/// Entrada de la firma binaria en un ASiC-S.
pub const ASIC_ENTRY_NAME_BINARY_SIGNATURE: &str = "META-INF/signature.p7s";
/// Entrada de la firma XML en un ASiC-S.
pub const ASIC_ENTRY_NAME_XML_SIGNATURE: &str = "META-INF/signatures.xml";
/// Entrada del tipo MIME en un ASiC-S.
pub const ASIC_ENTRY_NAME_MIMETYPE: &str = "mimetype";
/// Nombre base por defecto de los datos en un ASiC-S (`dataobject.<ext>`).
pub const ASIC_DEFAULT_DATA_OBJECT_NAME: &str = "dataobject";
/// Extensión por defecto de los datos en un ASiC-S.
pub const ASIC_DEFAULT_DATA_OBJECT_EXTENSION: &str = "bin";
/// Parámetro de política expandible (`ExtraParamsProcessor`).
pub const EXTRA_PARAM_EXP_POLICY: &str = "expPolicy";
/// Longitud máxima de una ruta en los extraParams (`MAX_PATH_SIZE`).
pub const MAX_PATH_SIZE: usize = 255;
/// 1 MiB (umbral de modo implícito en la política AGE para CAdES).
pub const SIZE_1MB: usize = 1024 * 1024;
/// Identificador de la política AGE (1.9).
pub const POLICY_ID_AGE: &str = "FirmaAGE";
/// Identificador de la política AGE 1.8.
pub const POLICY_ID_AGE_1_8: &str = "FirmaAGE18";
/// Identificador de la política AGE 1.9 (solo para preferencias; no lo
/// admite `expPolicy`).
pub const POLICY_ID_AGE_1_9: &str = "FirmaAGE19";
/// Algoritmo por defecto al calcular la huella de una política descargada.
pub const ADES_POLICY_DEFAULT_HASH_ALGORITHM: &str = "SHA-512";
/// Tiempo de espera por defecto (`-1` = el de la plataforma).
pub const DEFAULT_TIMEOUT: i32 = -1;
/// Propiedad de sistema (Java) que desactiva la validación TLS.
pub const JAVA_PARAM_DISABLE_SSL_CHECKS: &str = "disableSslChecks";
/// Propiedad de sistema (Java) con la lista de dominios seguros.
pub const JAVA_PARAM_SECURE_DOMAINS_LIST: &str = "secureDomainsList";
/// Parámetro adicional: operación sin interfaz gráfica.
pub const EXTRA_PARAM_HEADLESS: &str = "headless";
/// Parámetro adicional: omitir el diálogo de importación de certificados SSL.
pub const EXTRA_PARAM_SSL_OMIT_IMPORTATION_DIALOG: &str = "sslOmitImportationDialog";
/// Propiedad de sistema que bloquea la importación automática de
/// certificados de confianza.
pub const SYSTEM_PREFERENCE_BLOCK_AUTO_IMPORT_TRUSTED_CERTS: &str = "blockAutoImportTrustedCerts";
/// Nombre del almacén de confianza propio de AutoFirma (en `~/.afirma`).
pub const TRUSTSTORE_FILENAME: &str = "TrustedCertsKeystore.jks";
/// Contraseña del almacén de confianza propio de AutoFirma.
pub const TRUSTSTORE_PASSWORD: &str = "changeit";
/// Subdirectorio de AutoFirma en el directorio del usuario.
pub const AFIRMA_SUBDIR: &str = ".afirma";
/// Propiedad de sistema para no recortar las cadenas en el registro.
pub const SYSTEM_PROPERTY_ALLOW_EXTENDED_LOGS: &str = "allow.extended.logs";
/// Sufijo de los ficheros firmados en PKCS#1.
pub const PKCS1_SIGNED_FILE_SUFFIX: &str = ".p1";
/// Parámetro que se establece al confirmar una incompatibilidad con la
/// política AGE.
pub const EXTRA_PARAM_AVOID_AGE_POLICY_INCOMPATIBILITIES: &str = "avoidAGEPolicyIncompatibilities";
/// Clave del mensaje de incompatibilidad de política al firmar.
pub const REQUESTOR_AGE_POLICY_INCOMPATIBILITY_SIGN: &str = "agePolicyIncompatibilitySign";
/// Clave del mensaje de incompatibilidad de política al cofirmar.
pub const REQUESTOR_AGE_POLICY_INCOMPATIBILITY_COSIGN: &str = "agePolicyIncompatibilityCosign";
/// Clave del mensaje de incompatibilidad de política al contrafirmar.
pub const REQUESTOR_AGE_POLICY_INCOMPATIBILITY_COUNTERSIGN: &str = "agePolicyIncompatibilityCounterSign";
/// Operación de firma (`SignaturePolicyIncompatibilityException.OP_SIGN`).
pub const OP_SIGN: i32 = 1;
/// Operación de cofirma.
pub const OP_COSIGN: i32 = 2;
/// Operación de contrafirma.
pub const OP_COUNTERSIGN: i32 = 3;
/// Parámetro que se establece al confirmar la firma sobre una firma longeva.
pub const EXTRA_PARAM_ALLOW_SIGN_LT_SIGNATURE: &str = "allowSignLTSignature";
/// Clave del mensaje de firma longeva.
pub const REQUESTOR_SIGNING_LTS: &str = "signingLts";
/// Clave del mensaje de firma longeva posible.
pub const REQUESTOR_SIGNING_LTS_POSSIBLE: &str = "signingLtsPossible";
/// Formato de `AOSignInfo` cuando se construye con `null`.
pub const SIGN_INFO_UNKNOWN_FORMAT: &str = "Desconocido";
/// Identificador del almacén del sistema (`KeyStoreDialogManager`).
pub const KEYSTORE_ID_SYSTEM: i32 = 1;
/// Identificador del almacén de Mozilla.
pub const KEYSTORE_ID_MOZILLA: i32 = 2;
/// Identificador de un almacén PKCS#12.
pub const KEYSTORE_ID_PKCS12: i32 = 3;
/// Identificador del DNIe.
pub const KEYSTORE_ID_DNIE: i32 = 4;
/// Identificador de un almacén PKCS#11.
pub const KEYSTORE_ID_PKCS11: i32 = 5;
/// Versiones del protocolo `afirma://` (`ProtocolVersion`).
pub const PROTOCOL_VERSIONS: [&str; 6] = ["0", "1", "2", "3", "4", "4.1"];
/// Prefijo de categoría de error: hardware.
pub const ERROR_HARDWARE: &str = "1";
/// Prefijo de categoría de error: interno.
pub const ERROR_INTERNAL: &str = "2";
/// Prefijo de categoría de error: terceros.
pub const ERROR_THIRD_PARTY: &str = "3";
/// Prefijo de categoría de error: comunicación.
pub const ERROR_COMMUNICATION: &str = "4";
/// Prefijo de categoría de error: funcional.
pub const ERROR_FUNCTIONAL: &str = "5";
/// Prefijo de categoría de error: petición.
pub const ERROR_REQUEST: &str = "6";
/// Prefijo de categoría de error: petición del navegador.
pub const ERROR_REQUEST_FROM_BROWSER: &str = "62";
/// Prefijo de categoría de error: servicio trifásico.
pub const ERROR_TRIPHASE_SERVICE: &str = "3004";

// ---------------------------------------------------------------------------
// Preferencias de formato por defecto (§4.4)
// ---------------------------------------------------------------------------

/// Preferencia: formato para PDF.
pub const PREFERENCE_DEFAULT_SIGNATURE_FORMAT_PDF: &str = "defaultSignatureFormatPdf";
/// Preferencia: formato para OOXML.
pub const PREFERENCE_DEFAULT_SIGNATURE_FORMAT_OOXML: &str = "defaultSignatureFormatOoxml";
/// Preferencia: formato para FacturaE.
pub const PREFERENCE_DEFAULT_SIGNATURE_FORMAT_FACTURAE: &str = "defaultSignatureFormatFacturae";
/// Preferencia: formato para ODF.
pub const PREFERENCE_DEFAULT_SIGNATURE_FORMAT_ODF: &str = "defaultSignatureFormatOdf";
/// Preferencia: formato para XML.
pub const PREFERENCE_DEFAULT_SIGNATURE_FORMAT_XML: &str = "defaultSignatureFormatXml";
/// Preferencia: formato para binarios.
pub const PREFERENCE_DEFAULT_SIGNATURE_FORMAT_BIN: &str = "defaultSignatureFormatBin";
/// Valor por defecto de `defaultSignatureFormatPdf`.
pub const DEFAULT_SIGNATURE_FORMAT_PDF: &str = SIGN_FORMAT_PADES;
/// Valor por defecto de `defaultSignatureFormatOoxml` (CAdES, no OOXML).
pub const DEFAULT_SIGNATURE_FORMAT_OOXML: &str = SIGN_FORMAT_CADES;
/// Valor por defecto de `defaultSignatureFormatFacturae`.
pub const DEFAULT_SIGNATURE_FORMAT_FACTURAE: &str = SIGN_FORMAT_FACTURAE;
/// Valor por defecto de `defaultSignatureFormatOdf` (CAdES, no ODF).
pub const DEFAULT_SIGNATURE_FORMAT_ODF: &str = SIGN_FORMAT_CADES;
/// Valor por defecto de `defaultSignatureFormatXml`.
pub const DEFAULT_SIGNATURE_FORMAT_XML: &str = SIGN_FORMAT_XADES;
/// Valor por defecto de `defaultSignatureFormatBin`.
pub const DEFAULT_SIGNATURE_FORMAT_BIN: &str = SIGN_FORMAT_CADES;

// ---------------------------------------------------------------------------
// §1.7 Cifrado (`es.gob.afirma.core.ciphers.CipherConstants`)
// ---------------------------------------------------------------------------

/// Constantes de cifrado (`CipherConstants`). Solo se usan como modelo; los
/// flujos de firma de AutoFirma no cifran.
pub mod cipher {
    use std::fmt;

    /// Algoritmo de cifrado (`AOCipherAlgorithm`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum CipherAlgorithm {
        Aes,
        Blowfish,
        Des,
        TripleDes,
        PbeWithMd5AndDes,
        PbeWithSha1AndDesede,
        PbeWithSha1AndRc2_40,
        HmacMd5,
        HmacSha1,
        HmacSha256,
        HmacSha384,
        HmacSha512,
    }

    impl CipherAlgorithm {
        /// Todos los algoritmos, en el orden de Java.
        pub const ALL: [CipherAlgorithm; 12] = [
            Self::Aes,
            Self::Blowfish,
            Self::Des,
            Self::TripleDes,
            Self::PbeWithMd5AndDes,
            Self::PbeWithSha1AndDesede,
            Self::PbeWithSha1AndRc2_40,
            Self::HmacMd5,
            Self::HmacSha1,
            Self::HmacSha256,
            Self::HmacSha384,
            Self::HmacSha512,
        ];

        /// Nombre del algoritmo.
        pub fn name(self) -> &'static str {
            match self {
                Self::Aes => "AES",
                Self::Blowfish => "Blowfish",
                Self::Des => "DES",
                Self::TripleDes => "DESede",
                Self::PbeWithMd5AndDes => "PBEWithMD5AndDES",
                Self::PbeWithSha1AndDesede => "PBEWithSHA1AndDESede",
                Self::PbeWithSha1AndRc2_40 => "PBEWithSHA1AndRC2_40",
                Self::HmacMd5 => "HmacMD5",
                Self::HmacSha1 => "HmacSHA1",
                Self::HmacSha256 => "HmacSHA256",
                Self::HmacSha384 => "HmacSHA384",
                Self::HmacSha512 => "HmacSHA512",
            }
        }

        /// OID del algoritmo.
        pub fn oid(self) -> &'static str {
            match self {
                Self::Aes => "2.16.840.1.101.3.4.1",
                Self::Blowfish => "1.3.6.1.4.1.3029.1.1.1",
                Self::Des => "1.2.840.113549.3.6",
                Self::TripleDes => "1.2.840.113549.3.7",
                Self::PbeWithMd5AndDes => "1.2.840.113549.1.5.3",
                Self::PbeWithSha1AndDesede => "1.2.840.113549.1.5.10",
                Self::PbeWithSha1AndRc2_40 => "1.2.840.113549.1.5.11",
                Self::HmacMd5 => "1.3.6.1.5.5.8.1.1",
                Self::HmacSha1 => "1.2.840.113549.2.7",
                Self::HmacSha256 => "1.2.840.113549.2.9",
                Self::HmacSha384 => "1.2.840.113549.2.10",
                Self::HmacSha512 => "1.2.840.113549.2.11",
            }
        }

        /// Indica si el algoritmo admite contraseña (PBE).
        pub fn supports_password(self) -> bool {
            matches!(self, Self::PbeWithMd5AndDes | Self::PbeWithSha1AndDesede | Self::PbeWithSha1AndRc2_40)
        }

        /// Indica si el algoritmo admite clave.
        pub fn supports_key(self) -> bool {
            !self.supports_password()
        }

        /// Busca un algoritmo por su nombre sin distinguir mayúsculas.
        pub fn from_name(name: &str) -> Option<Self> {
            Self::ALL.into_iter().find(|a| a.name().eq_ignore_ascii_case(name))
        }
    }

    /// Algoritmo de cifrado por defecto.
    pub const DEFAULT_CIPHER_ALGORITHM: CipherAlgorithm = CipherAlgorithm::Aes;

    /// Relleno (`AOCipherPadding`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum CipherPadding {
        Pkcs5Padding,
        Iso10126Padding,
        NoPadding,
    }

    impl CipherPadding {
        /// Nombre del relleno.
        pub fn name(self) -> &'static str {
            match self {
                Self::Pkcs5Padding => "PKCS5PADDING",
                Self::Iso10126Padding => "ISO10126PADDING",
                Self::NoPadding => "NOPADDING",
            }
        }

        /// Busca un relleno por su nombre (sin distinguir mayúsculas).
        pub fn from_name(name: &str) -> Option<Self> {
            [Self::Pkcs5Padding, Self::Iso10126Padding, Self::NoPadding]
                .into_iter()
                .find(|p| p.name().eq_ignore_ascii_case(name))
        }
    }

    /// Modo de bloque (`AOCipherBlockMode`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum CipherBlockMode {
        Ecb,
        Cbc,
        Pcbc,
        Ctr,
        Cfb,
        Ofb,
    }

    impl CipherBlockMode {
        /// Nombre del modo.
        pub fn name(self) -> &'static str {
            match self {
                Self::Ecb => "ECB",
                Self::Cbc => "CBC",
                Self::Pcbc => "PCBC",
                Self::Ctr => "CTR",
                Self::Cfb => "CFB",
                Self::Ofb => "OFB",
            }
        }

        /// Busca un modo por su nombre (sin distinguir mayúsculas).
        pub fn from_name(name: &str) -> Option<Self> {
            [Self::Ecb, Self::Cbc, Self::Pcbc, Self::Ctr, Self::Cfb, Self::Ofb]
                .into_iter()
                .find(|m| m.name().eq_ignore_ascii_case(name))
        }
    }

    /// Configuración de cifrado (`AOCipherConfig`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CipherConfig {
        pub algorithm: CipherAlgorithm,
        pub mode: CipherBlockMode,
        pub padding: CipherPadding,
    }

    impl CipherConfig {
        /// Construye la configuración aplicando los valores por defecto de
        /// Java: algoritmo AES; modo CBC para los algoritmos PBE y ECB para el
        /// resto; relleno PKCS5PADDING.
        pub fn new(
            algorithm: Option<CipherAlgorithm>,
            mode: Option<CipherBlockMode>,
            padding: Option<CipherPadding>,
        ) -> Self {
            let algorithm = algorithm.unwrap_or(DEFAULT_CIPHER_ALGORITHM);
            let mode =
                mode.unwrap_or(if algorithm.supports_password() { CipherBlockMode::Cbc } else { CipherBlockMode::Ecb });
            CipherConfig { algorithm, mode, padding: padding.unwrap_or(CipherPadding::Pkcs5Padding) }
        }

        /// Interpreta `ALGO[/MODO/RELLENO]` (`AOCipherConfig.parse`). El modo
        /// y el relleno solo se leen si hay exactamente tres partes.
        pub fn parse(text: &str) -> Result<Self, String> {
            let parts: Vec<&str> = text.split('/').collect();
            let algorithm = CipherAlgorithm::from_name(parts[0])
                .ok_or_else(|| format!("Algoritmo de cifrado no soportado: {}", parts[0]))?;
            let (mode, padding) = if parts.len() == 3 {
                (CipherBlockMode::from_name(parts[1]), CipherPadding::from_name(parts[2]))
            } else {
                (None, None)
            };
            Ok(Self::new(Some(algorithm), mode, padding))
        }
    }

    impl fmt::Display for CipherConfig {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}/{}/{}", self.algorithm.name(), self.mode.name(), self.padding.name())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cipher_config() {
            assert_eq!(CipherConfig::parse("AES").unwrap().to_string(), "AES/ECB/PKCS5PADDING");
            assert_eq!(
                CipherConfig::parse("pbewithmd5anddes").unwrap().to_string(),
                "PBEWithMD5AndDES/CBC/PKCS5PADDING"
            );
            assert_eq!(CipherConfig::parse("DESede/CBC/NoPadding").unwrap().to_string(), "DESede/CBC/NOPADDING");
            assert_eq!(CipherConfig::parse("AES/CBC").unwrap().to_string(), "AES/ECB/PKCS5PADDING");
            assert!(CipherConfig::parse("RC4").is_err());
            assert_eq!(CipherAlgorithm::TripleDes.oid(), "1.2.840.113549.3.7");
            assert!(CipherAlgorithm::HmacSha256.supports_key());
        }
    }
}
