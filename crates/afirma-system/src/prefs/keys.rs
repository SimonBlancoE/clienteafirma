//! Modelo tipado de **todas** las claves de preferencias de AutoFirma, con los nombres
//! exactos, los valores por defecto de `preferences.properties`, la lista de claves
//! protegidas de Java (`PreferencesManager.isProtectedPreference`) y la ampliación de
//! claves bloqueables de la especificación (§4.4.3).

use std::marker::PhantomData;

/// Tipo de valor de una preferencia (todas se guardan como cadenas).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Kind {
    /// `"true"` / `"false"`.
    Bool,
    /// Texto libre.
    Str,
    /// Entero decimal.
    Int,
    /// Uno de los literales indicados.
    Enum(&'static [&'static str]),
}

/// Sección (pestaña) de la interfaz a la que pertenece una clave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Section {
    /// Claves ocultas / globales.
    Hidden,
    /// Pestaña «General».
    General,
    /// Subdiálogo «Formatos de firma».
    Formats,
    /// Configuración de proxy.
    Proxy,
    /// Pestaña «Firmas PAdES (PDF)».
    Pades,
    /// Apariencia de la firma PDF visible.
    PdfVisible,
    /// Pestaña «Firmas CAdES».
    Cades,
    /// Pestaña «Firmas XAdES».
    Xades,
    /// Pestaña «Factura Electrónica».
    Facturae,
    /// Pestaña «Almacenes de claves».
    Keystores,
    /// Claves de administración.
    Admin,
    /// Nodo interno (`internalpreferences`).
    Internal,
}

/// Descripción de una clave de preferencia.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct KeyInfo {
    /// Nombre exacto (contrato con `.afconfig`, registro y directivas).
    pub name: &'static str,
    /// Tipo.
    pub kind: Kind,
    /// Valor por defecto de `preferences.properties` (`None` = ausente).
    pub default: Option<&'static str>,
    /// Sección.
    pub section: Section,
    /// En la lista de claves protegidas de Java.
    pub protected: bool,
    /// Bloqueable por `preferencesBlocked` (protegidas + las que la interfaz Java también
    /// deshabilita o trata como política).
    pub lockable: bool,
    /// Clave de administración: en modo estricto solo se lee de las capas de sistema y directiva.
    pub admin_only: bool,
    /// Pertenece al nodo interno (`/es/gob/afirma/standalone/ui/internalpreferences`).
    pub internal: bool,
    /// Exclusiva del sistema (nunca se lee de la capa de usuario, ni siquiera en Java).
    pub system_exclusive: bool,
}

impl KeyInfo {
    const BASE: KeyInfo = KeyInfo {
        name: "",
        kind: Kind::Str,
        default: None,
        section: Section::Hidden,
        protected: false,
        lockable: false,
        admin_only: false,
        internal: false,
        system_exclusive: false,
    };

    /// Comprueba si un valor es admisible para la clave.
    pub fn accepts(&self, value: &str) -> bool {
        match self.kind {
            Kind::Bool => value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false"),
            Kind::Str => true,
            Kind::Int => value.trim().parse::<i64>().is_ok(),
            // Las claves de enumeración aceptan también la cadena vacía si su valor por
            // defecto es vacío (p. ej. algoritmo de huella de política no configurada).
            Kind::Enum(vals) => {
                vals.contains(&value) || (value.is_empty() && self.default == Some(""))
            }
        }
    }
}

/// Clave tipada.
pub struct Key<T> {
    /// Descripción de la clave.
    pub info: &'static KeyInfo,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for Key<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Key<T> {}

impl<T> std::fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.info.name)
    }
}

impl<T> Key<T> {
    /// Crea la clave.
    pub const fn new(info: &'static KeyInfo) -> Self {
        Self {
            info,
            _t: PhantomData,
        }
    }

    /// Nombre de la clave.
    pub const fn name(&self) -> &'static str {
        self.info.name
    }
}

/// Conversión entre el valor tipado y su representación textual en las preferencias.
pub trait PrefValue: Sized {
    /// Interpreta el texto guardado (`None` si no es válido).
    fn parse_pref(s: &str) -> Option<Self>;
    /// Representación textual.
    fn to_pref(&self) -> String;
}

impl PrefValue for bool {
    fn parse_pref(s: &str) -> Option<Self> {
        // java.util.prefs.Preferences.getBoolean: "true"/"false" sin distinguir mayúsculas.
        if s.eq_ignore_ascii_case("true") {
            Some(true)
        } else if s.eq_ignore_ascii_case("false") {
            Some(false)
        } else {
            None
        }
    }
    fn to_pref(&self) -> String {
        if *self { "true".into() } else { "false".into() }
    }
}

impl PrefValue for String {
    fn parse_pref(s: &str) -> Option<Self> {
        Some(s.to_string())
    }
    fn to_pref(&self) -> String {
        self.clone()
    }
}

impl PrefValue for i32 {
    fn parse_pref(s: &str) -> Option<Self> {
        s.trim().parse().ok()
    }
    fn to_pref(&self) -> String {
        self.to_string()
    }
}

macro_rules! pref_enum {
    ($(#[$m:meta])* $name:ident { $( $(#[$vm:meta])* $var:ident => $lit:literal ),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub enum $name { $( $(#[$vm])* #[serde(rename = $lit)] $var ),+ }

        impl $name {
            /// Literales admitidos, en el orden de la interfaz.
            pub const VALUES: &'static [&'static str] = &[$($lit),+];
            /// Literal exacto.
            pub fn as_str(&self) -> &'static str {
                match self { $( $name::$var => $lit ),+ }
            }
        }

        impl PrefValue for $name {
            fn parse_pref(s: &str) -> Option<Self> {
                match s { $( $lit => Some($name::$var), )+ _ => None }
            }
            fn to_pref(&self) -> String {
                self.as_str().to_string()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

pref_enum!(
    /// Algoritmo de huella de la firma (`signatureHashAlgorithm`).
    HashAlgorithm { Sha1 => "SHA1", Sha512 => "SHA512", Sha384 => "SHA384", Sha256 => "SHA256" }
);
pref_enum!(
    /// Nombre de firmador (`AOSignConstants`) usado en `defaultSignatureFormat*`.
    SignatureFormat {
        Pades => "PAdES",
        Cades => "CAdES",
        Xades => "XAdES",
        Facturae => "FacturaE",
        Ooxml => "OOXML (Office Open XML)",
        Odf => "ODF (Open Document Format)",
    }
);
pref_enum!(
    /// Formato XAdES (`xadesSignFormat`).
    XadesSignFormat { Enveloped => "XAdES Enveloped", Enveloping => "XAdES Enveloping", Detached => "XAdES Detached" }
);
pref_enum!(
    /// Subfiltro PAdES (`padesBasicFormat`).
    PadesSubFilter { EtsiCadesDetached => "ETSI.CAdES.detached", AdbePkcs7Detached => "adbe.pkcs7.detached" }
);
pref_enum!(
    /// Operación sobre firmas existentes (`cadesMultisign`, `xadesMultisign`).
    MultisignOp { Cosign => "cosign", CountersignLeafs => "countersignLeafs", CountersignTree => "countersignTree" }
);
pref_enum!(
    /// Algoritmo de huella de la política de firma.
    PolicyHashAlgorithm { Sha1 => "SHA1", Sha512 => "SHA-512", Sha384 => "SHA-384", Sha256 => "SHA-256" }
);
pref_enum!(
    /// Política de Factura Electrónica (`facturaEPolicy`).
    FacturaePolicy { V3_1 => "3.1", V3_0 => "3.0" }
);
pref_enum!(
    /// Papel del firmante de la factura (`facturaeSignerRole`).
    FacturaeRole { Emisor => "Emisor", Receptor => "Receptor", Tercero => "Tercero" }
);
pref_enum!(
    /// Tipo de proxy (`proxyType`).
    ProxyType { None => "NONE", System => "SYSTEM", Custom => "CUSTOM" }
);
pref_enum!(
    /// Nivel de certificación PDF (`padesCertificationLevel`).
    CertificationLevel { NotCertified => "0", Author => "1", AuthorForms => "2", Common => "3" }
);
pref_enum!(
    /// Familia tipográfica de la firma visible (`pdfLayer2FontFamily`).
    FontFamily { Courier => "0", Helvetica => "1", TimesRoman => "2" }
);
pref_enum!(
    /// Color del texto de la firma visible (`pdfLayer2FontColor`).
    FontColor {
        Black => "black",
        White => "white",
        LightGray => "lightGray",
        Gray => "gray",
        DarkGray => "darkGray",
        Red => "red",
        Pink => "pink",
    }
);
pref_enum!(
    /// Rotación de la firma visible (`pdfSignatureRotation`).
    Rotation { R0 => "0", R90 => "90", R180 => "180", R270 => "270" }
);
pref_enum!(
    /// Pestaña del diálogo de selección de certificados (`certView`).
    CertView { Personal => "PERSONAL", Representative => "REPRESENTATIVE", Pseudonym => "PSEUDONYM" }
);

impl MultisignOp {
    /// Interpretación de Java: cualquier valor desconocido equivale a `countersignTree`.
    pub fn from_pref_lenient(s: &str) -> MultisignOp {
        MultisignOp::parse_pref(s).unwrap_or(MultisignOp::CountersignTree)
    }
}

const PDF_FORMATS: &[&str] = &["PAdES", "CAdES", "XAdES"];
const FACTURAE_FORMATS: &[&str] = &["FacturaE", "XAdES", "CAdES"];
const OOXML_FORMATS: &[&str] = &["OOXML (Office Open XML)", "CAdES", "XAdES"];
const ODF_FORMATS: &[&str] = &["ODF (Open Document Format)", "CAdES", "XAdES"];
const XML_FORMATS: &[&str] = &["XAdES", "CAdES"];
const BIN_FORMATS: &[&str] = &["CAdES", "XAdES"];

/// Texto por defecto de la firma visible PDF.
pub const DEFAULT_LAYER2_TEXT: &str = "Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$";

/// Valor de `defaultKeystore` para «almacén por defecto del sistema».
pub const VALUE_KEYSTORE_DEFAULT: &str = "default";

macro_rules! define_keys {
    ($( $(#[doc = $doc:literal])* $id:ident : $ty:ty = $name:literal { $($field:ident : $val:expr),* $(,)? } ;)*) => {
        $( $(#[doc = $doc])* pub const $id: Key<$ty> = Key::new(&KeyInfo { name: $name, $($field: $val,)* ..KeyInfo::BASE }); )*
        /// Todas las claves del nodo principal y del nodo interno, en el orden de la especificación.
        pub const ALL: &[&KeyInfo] = &[ $( $id.info, )* ];
    };
}

define_keys! {
    // ---- Claves ocultas / globales (§4.5.1) ----
    /// Idioma de la interfaz (`ll_CC`).
    LOCALE: String = "default.locale" { default: Some("es_ES") };
    /// Bloqueo de preferencias por el administrador.
    PREFERENCES_BLOCKED: bool = "preferencesBlocked" { kind: Kind::Bool, default: Some("false"), section: Section::Admin, admin_only: true };
    /// Aviso de versión de Java no soportada (obsoleta en Rust).
    CHECK_JAVA_VERSION: bool = "checkJavaVersion" { kind: Kind::Bool, default: Some("true") };
    /// Clave muerta del fichero de valores por defecto (el actualizador usa otro nodo).
    LAST_CHECK_DATE_DEAD: String = "lastCheckDate" { default: Some("") };
    /// Clave muerta, sin uso.
    JMULTICARD_CACHE_PASSWORD: bool = "jmulticardCachePassword" { kind: Kind::Bool, default: Some("false") };

    // ---- General (§4.5.2) ----
    /// No pedir confirmación al cerrar.
    OMIT_ASK_ON_CLOSE: bool = "omitAskOnClose" { kind: Kind::Bool, default: Some("false"), section: Section::General };
    /// Buscar actualizaciones al inicio.
    CHECK_FOR_UPDATES: bool = "checkForUpdates" { kind: Kind::Bool, default: Some("true"), section: Section::General, protected: true, lockable: true };
    /// Controlador interno de DNIe/CERES.
    ENABLED_JMULTICARD: bool = "enabledJmulticard" { kind: Kind::Bool, default: Some("true"), section: Section::General, protected: true, lockable: true };
    /// Optimización para VDI.
    VDI_OPTIMIZATION: bool = "vdiOptimization" { kind: Kind::Bool, default: Some("false"), section: Section::General };
    /// Diálogo de carga en llamadas desde el navegador.
    ENABLE_PROGRESS_DIALOG: bool = "enableProgressDialog" { kind: Kind::Bool, default: Some("true"), section: Section::General };
    /// Algoritmo de huella de las firmas de la interfaz.
    SIGNATURE_HASH_ALGORITHM: HashAlgorithm = "signatureHashAlgorithm" { kind: Kind::Enum(HashAlgorithm::VALUES), default: Some("SHA256"), section: Section::General, protected: true, lockable: true };
    /// Formato por defecto para PDF.
    DEFAULT_FORMAT_PDF: SignatureFormat = "defaultSignatureFormatPdf" { kind: Kind::Enum(PDF_FORMATS), default: Some("PAdES"), section: Section::Formats, protected: true, lockable: true };
    /// Formato por defecto para OOXML (por defecto CAdES).
    DEFAULT_FORMAT_OOXML: SignatureFormat = "defaultSignatureFormatOoxml" { kind: Kind::Enum(OOXML_FORMATS), default: Some("CAdES"), section: Section::Formats, protected: true, lockable: true };
    /// Formato por defecto para facturas electrónicas.
    DEFAULT_FORMAT_FACTURAE: SignatureFormat = "defaultSignatureFormatFacturae" { kind: Kind::Enum(FACTURAE_FORMATS), default: Some("FacturaE"), section: Section::Formats, protected: true, lockable: true };
    /// Formato por defecto para ODF (por defecto CAdES).
    DEFAULT_FORMAT_ODF: SignatureFormat = "defaultSignatureFormatOdf" { kind: Kind::Enum(ODF_FORMATS), default: Some("CAdES"), section: Section::Formats, protected: true, lockable: true };
    /// Formato por defecto para XML genérico.
    DEFAULT_FORMAT_XML: SignatureFormat = "defaultSignatureFormatXml" { kind: Kind::Enum(XML_FORMATS), default: Some("XAdES"), section: Section::Formats, protected: true, lockable: true };
    /// Formato por defecto para el resto de ficheros.
    DEFAULT_FORMAT_BIN: SignatureFormat = "defaultSignatureFormatBin" { kind: Kind::Enum(BIN_FORMATS), default: Some("CAdES"), section: Section::Formats, protected: true, lockable: true };
    /// Solicitar confirmación para firmar.
    CONFIRM_TO_SIGN: bool = "confirmToSign" { kind: Kind::Bool, default: Some("true"), section: Section::General };
    /// Permitir añadir firmas a documentos con firmas no válidas.
    ALLOW_INVALID_SIGNATURES: bool = "allowInvalidSignatures" { kind: Kind::Bool, default: Some("false"), section: Section::General, protected: true, lockable: true };
    /// Sobrescribir ficheros en la firma masiva.
    MASSIVE_OVERRIDE: bool = "massiveOverride" { kind: Kind::Bool, default: Some("false"), section: Section::General };
    /// Aceptar solo conexiones seguras.
    SECURE_CONNECTIONS: bool = "secureConnections" { kind: Kind::Bool, default: Some("true"), section: Section::General, protected: true, lockable: true };
    /// Dominios seguros (sin validación TLS), separados por comas.
    SECURE_DOMAINS_LIST: String = "secureDomainsList" { section: Section::General };

    // ---- Proxy (§4.12) ----
    /// Proxy (clave heredada).
    PROXY_SELECTED: bool = "proxySelected" { kind: Kind::Bool, default: Some("false"), section: Section::Proxy };
    /// Tipo de proxy.
    PROXY_TYPE: ProxyType = "proxyType" { kind: Kind::Enum(ProxyType::VALUES), default: Some("NONE"), section: Section::Proxy };
    /// Servidor proxy.
    PROXY_HOST: String = "proxyHost" { default: Some(""), section: Section::Proxy };
    /// Puerto del proxy.
    PROXY_PORT: String = "proxyPort" { default: Some(""), section: Section::Proxy };
    /// Usuario del proxy.
    PROXY_USERNAME: String = "proxyUsername" { section: Section::Proxy };
    /// Contraseña del proxy (cifrada, ver [`crate::prefs::proxy`]).
    PROXY_PASSWORD: String = "proxyPassword" { section: Section::Proxy };
    /// Excepciones del proxy (separadas por `|`).
    PROXY_EXCLUDED_URLS: String = "proxyExcludedUrls" { section: Section::Proxy };

    // ---- PAdES (§4.5.4) ----
    /// Identificador de la política PAdES.
    PADES_POLICY_IDENTIFIER: String = "padesPolicyIdentifier" { default: Some(""), section: Section::Pades, protected: true, lockable: true };
    /// Huella de la política PAdES.
    PADES_POLICY_HASH: String = "padesPolicyIdentifierHash" { default: Some(""), section: Section::Pades, protected: true, lockable: true };
    /// Algoritmo de la huella de la política PAdES.
    PADES_POLICY_HASH_ALGORITHM: String = "padesPolicyIdentifierHashAlgorithm" { kind: Kind::Enum(PolicyHashAlgorithm::VALUES), default: Some(""), section: Section::Pades, protected: true, lockable: true };
    /// Calificador de la política PAdES.
    PADES_POLICY_QUALIFIER: String = "padesPolicyQualifier" { default: Some(""), section: Section::Pades, protected: true, lockable: true };
    /// Subfiltro PAdES.
    PADES_BASIC_FORMAT: PadesSubFilter = "padesBasicFormat" { kind: Kind::Enum(PadesSubFilter::VALUES), default: Some("ETSI.CAdES.detached"), section: Section::Pades, protected: true, lockable: true };
    /// Firmas visibles por defecto.
    PADES_VISIBLE_SIGNATURE: bool = "padesVisibleSignature" { kind: Kind::Bool, default: Some("false"), section: Section::Pades };
    /// Ofuscar identificadores en firmas visibles.
    PADES_OBFUSCATE_CERT_INFO: bool = "padesObfuscateCertInfo" { kind: Kind::Bool, default: Some("true"), section: Section::Pades };
    /// Marca visible por defecto.
    PADES_VISIBLE_STAMP: bool = "padesVisibleStamp" { kind: Kind::Bool, default: Some("false"), section: Section::Pades };
    /// `true` = **sí** comprobar PDF Shadow Attack (nombre invertido).
    ALLOW_SHADOW_ATTACK: bool = "allowShadowAttack" { kind: Kind::Bool, default: Some("false"), section: Section::Pades, protected: true, lockable: true };
    /// Permitir generar PDF certificado.
    ALLOW_CERTIFIED_PDF: bool = "allowCertifiedPDF" { kind: Kind::Bool, default: Some("false"), section: Section::Pades, lockable: true };
    /// Nivel de certificación por defecto.
    PADES_CERTIFICATION_LEVEL: CertificationLevel = "padesCertificationLevel" { kind: Kind::Enum(CertificationLevel::VALUES), default: Some("0"), section: Section::Pades, lockable: true };
    /// Razón de la firma.
    PADES_SIGN_REASON: String = "padesSignReason" { default: Some(""), section: Section::Pades };
    /// Ciudad de la firma PAdES.
    PADES_SIGN_PRODUCTION_CITY: String = "padesSignProductionCity" { default: Some(""), section: Section::Pades };
    /// Contacto del firmante.
    PADES_SIGNER_CONTACT: String = "padesSignerContact" { default: Some(""), section: Section::Pades };

    // ---- Firma PDF visible (§4.5.5) ----
    /// Texto de la firma visible.
    PDF_LAYER2_TEXT: String = "pdfLayer2Text" { default: Some(DEFAULT_LAYER2_TEXT), section: Section::PdfVisible };
    /// Familia tipográfica.
    PDF_LAYER2_FONT_FAMILY: FontFamily = "pdfLayer2FontFamily" { kind: Kind::Enum(FontFamily::VALUES), default: Some("0"), section: Section::PdfVisible };
    /// Tamaño de letra.
    PDF_LAYER2_FONT_SIZE: i32 = "pdfLayer2FontSize" { kind: Kind::Int, default: Some("12"), section: Section::PdfVisible };
    /// Estilo de letra (máscara: 1 negrita, 2 cursiva, 4 subrayado, 8 tachado).
    PDF_LAYER2_FONT_STYLE: i32 = "pdfLayer2FontStyle" { kind: Kind::Int, default: Some("0"), section: Section::PdfVisible };
    /// Color del texto.
    PDF_LAYER2_FONT_COLOR: FontColor = "pdfLayer2FontColor" { kind: Kind::Enum(FontColor::VALUES), default: Some("black"), section: Section::PdfVisible };
    /// Rotación.
    PDF_SIGNATURE_ROTATION: Rotation = "pdfSignatureRotation" { kind: Kind::Enum(Rotation::VALUES), default: Some("0"), section: Section::PdfVisible };
    /// Imagen de rúbrica.
    PDF_SIGNATURE_IMAGE: String = "pdfSignatureImage" { default: Some(""), section: Section::PdfVisible };

    // ---- CAdES (§4.5.6) ----
    /// Identificador de la política CAdES.
    CADES_POLICY_IDENTIFIER: String = "cadesPolicyIdentifier" { default: Some(""), section: Section::Cades, protected: true, lockable: true };
    /// Huella de la política CAdES.
    CADES_POLICY_HASH: String = "cadesPolicyIdentifierHash" { default: Some(""), section: Section::Cades, protected: true, lockable: true };
    /// Algoritmo de la huella de la política CAdES.
    CADES_POLICY_HASH_ALGORITHM: String = "cadesPolicyIdentifierHashAlgorithm" { kind: Kind::Enum(PolicyHashAlgorithm::VALUES), default: Some(""), section: Section::Cades, protected: true, lockable: true };
    /// Calificador de la política CAdES.
    CADES_POLICY_QUALIFIER: String = "cadesPolicyQualifier" { default: Some(""), section: Section::Cades, protected: true, lockable: true };
    /// Firma implícita (con los datos).
    CADES_IMPLICIT_MODE: bool = "cadesImplicitMode" { kind: Kind::Bool, default: Some("true"), section: Section::Cades, protected: true, lockable: true };
    /// Operación sobre firmas CAdES existentes.
    CADES_MULTISIGN: MultisignOp = "cadesMultisign" { kind: Kind::Enum(MultisignOp::VALUES), default: Some("cosign"), section: Section::Cades, lockable: true };

    // ---- XAdES (§4.5.7) ----
    /// Identificador de la política XAdES.
    XADES_POLICY_IDENTIFIER: String = "xadesPolicyIdentifier" { default: Some(""), section: Section::Xades, protected: true, lockable: true };
    /// Huella de la política XAdES.
    XADES_POLICY_HASH: String = "xadesPolicyIdentifierHash" { default: Some(""), section: Section::Xades, protected: true, lockable: true };
    /// Algoritmo de la huella de la política XAdES.
    XADES_POLICY_HASH_ALGORITHM: String = "xadesPolicyIdentifierHashAlgorithm" { kind: Kind::Enum(PolicyHashAlgorithm::VALUES), default: Some(""), section: Section::Xades, protected: true, lockable: true };
    /// Calificador de la política XAdES.
    XADES_POLICY_QUALIFIER: String = "xadesPolicyQualifier" { default: Some(""), section: Section::Xades, protected: true, lockable: true };
    /// Formato XAdES.
    XADES_SIGN_FORMAT: XadesSignFormat = "xadesSignFormat" { kind: Kind::Enum(XadesSignFormat::VALUES), default: Some("XAdES Detached"), section: Section::Xades, protected: true, lockable: true };
    /// Operación sobre firmas XAdES existentes.
    XADES_MULTISIGN: MultisignOp = "xadesMultisign" { kind: Kind::Enum(MultisignOp::VALUES), default: Some("cosign"), section: Section::Xades, lockable: true };
    /// Ciudad de la firma XAdES.
    XADES_PRODUCTION_CITY: String = "xadesSignatureProductionCity" { default: Some(""), section: Section::Xades };
    /// Provincia de la firma XAdES.
    XADES_PRODUCTION_PROVINCE: String = "xadesSignatureProductionProvince" { default: Some(""), section: Section::Xades };
    /// Código postal de la firma XAdES.
    XADES_PRODUCTION_POSTAL_CODE: String = "xadesSignatureProductionPostalCode" { default: Some(""), section: Section::Xades };
    /// País de la firma XAdES.
    XADES_PRODUCTION_COUNTRY: String = "xadesSignatureProductionCountry" { default: Some(""), section: Section::Xades };
    /// Cargo atribuido al firmante.
    XADES_SIGNER_CLAIMED_ROLE: String = "xadesSignerClaimedRole" { default: Some(""), section: Section::Xades };

    // ---- Factura electrónica (§4.5.8) ----
    /// Política de Factura Electrónica.
    FACTURAE_POLICY: FacturaePolicy = "facturaEPolicy" { kind: Kind::Enum(FacturaePolicy::VALUES), default: Some("3.1"), section: Section::Facturae, protected: true, lockable: true };
    /// Identificador de la política FacturaE (derivado).
    FACTURAE_POLICY_IDENTIFIER: String = "facturaePolicyIdentifier" { default: Some("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"), section: Section::Facturae, lockable: true };
    /// Huella de la política FacturaE (derivada).
    FACTURAE_POLICY_HASH: String = "facturaePolicyIdentifierHash" { default: Some("Ohixl6upD6av8N7pEvDABhEL6hM="), section: Section::Facturae, lockable: true };
    /// Algoritmo de la huella de la política FacturaE (derivado).
    FACTURAE_POLICY_HASH_ALGORITHM: String = "facturaePolicyIdentifierHashAlgorithm" { default: Some("SHA1"), section: Section::Facturae, lockable: true };
    /// Calificador de la política FacturaE (nunca se envía al firmador).
    FACTURAE_POLICY_QUALIFIER: String = "facturaePolicyQualifier" { section: Section::Facturae, lockable: true };
    /// Papel del firmante.
    FACTURAE_SIGNER_ROLE: FacturaeRole = "facturaeSignerRole" { kind: Kind::Enum(FacturaeRole::VALUES), default: Some("Emisor"), section: Section::Facturae };
    /// Ciudad de la firma de facturas.
    FACTURAE_PRODUCTION_CITY: String = "facturaeSignatureProductionCity" { default: Some(""), section: Section::Facturae };
    /// Provincia de la firma de facturas.
    FACTURAE_PRODUCTION_PROVINCE: String = "facturaeSignatureProductionProvince" { default: Some(""), section: Section::Facturae };
    /// Código postal de la firma de facturas.
    FACTURAE_PRODUCTION_POSTAL_CODE: String = "facturaeSignatureProductionPostalCode" { default: Some(""), section: Section::Facturae };
    /// País de la firma de facturas.
    FACTURAE_PRODUCTION_COUNTRY: String = "facturaeSignatureProductionCountry" { default: Some(""), section: Section::Facturae };

    // ---- Almacenes de claves (§4.5.9) ----
    /// Almacén por defecto (`default` o nombre de almacén / tarjeta).
    DEFAULT_KEYSTORE: String = "defaultKeystore" { default: Some(VALUE_KEYSTORE_DEFAULT), section: Section::Keystores };
    /// Ruta del PKCS#12 o biblioteca PKCS#11 del almacén por defecto.
    DEFAULT_LOCAL_KEYSTORE_PATH: String = "defaultLocalKeystorePath" { default: Some(""), section: Section::Keystores };
    /// Usar el almacén por defecto en las llamadas desde el navegador.
    USE_DEFAULT_STORE_IN_BROWSER_CALLS: bool = "useDefaultStoreInBrowserCalls" { kind: Kind::Bool, default: Some("false"), section: Section::Keystores, lockable: true };
    /// Omitir la pantalla inicial de DNIe.
    HIDE_DNIE_START_SCREEN: bool = "hideDnieStartScreen" { kind: Kind::Bool, default: Some("false"), section: Section::Keystores };
    /// Mostrar certificados caducados.
    SHOW_EXPIRED_CERTS: bool = "showExpiredCerts" { kind: Kind::Bool, default: Some("false"), section: Section::Keystores, protected: true, lockable: true };
    /// Solo certificados de firma (no repudio).
    USE_ONLY_SIGNATURE_CERTIFICATES: bool = "useOnlySignatureCertificates" { kind: Kind::Bool, default: Some("false"), section: Section::Keystores };
    /// Solo certificados de seudónimo.
    USE_ONLY_ALIAS_CERTIFICATES: bool = "useOnlyAliasCertificates" { kind: Kind::Bool, default: Some("false"), section: Section::Keystores };
    /// Omitir el certificado de autenticación del DNIe.
    SKIP_AUTH_CERT_DNIE: bool = "skipAuthCertDnie" { kind: Kind::Bool, default: Some("true"), section: Section::Keystores };

    // ---- Administración (§4.4.3) ----
    /// Permitir el almacén de confianza personal.
    ALLOW_PERSONAL_TRUSTSTORE: bool = "allowPersonalTruststore" { kind: Kind::Bool, default: Some("true"), section: Section::Admin, admin_only: true };
    /// Permitir importar automáticamente certificados de servidor no confiables.
    ALLOW_AUTO_IMPORT_TRUSTED_CERTS: bool = "allowAutoImportTrustedCerts" { kind: Kind::Bool, default: Some("true"), section: Section::Admin, admin_only: true };

    // ---- Nodo interno (§4.4.3, §4.11) ----
    /// Origen de la configuración del sistema (URL https o ruta local).
    CONFIG_FILE_URL: String = "configFileUrl" { section: Section::Internal, internal: true, system_exclusive: true, admin_only: true };
    /// Permitir la actualización diaria de la configuración remota.
    ALLOW_UPDATE_CONFIG: bool = "allowUpdateConfig" { kind: Kind::Bool, section: Section::Internal, internal: true, system_exclusive: true, admin_only: true };
    /// SHA-256 (hexadecimal en mayúsculas) del último fichero de configuración importado.
    CONFIG_FILE_SHA256: String = "configFileSHA256" { section: Section::Internal, internal: true };
    /// Fecha de la última comprobación (`yyyyMMdd`).
    CONFIG_DATE: String = "configDate" { section: Section::Internal, internal: true };
    /// Exigir ficheros de preferencias firmados (nombre con errata, se conserva).
    REQUIRE_SIGNED_PREFERENCES: bool = "requireSignedPrerefences" { kind: Kind::Bool, section: Section::Internal, internal: true, admin_only: true };
    /// Base64(SHA-256(DER)) del certificado autorizado a firmar la configuración (con errata).
    CERT_HASH_TO_SIGNED_PREFERENCES: String = "certHashToSignedPrerefences" { section: Section::Internal, internal: true, admin_only: true };
}

/// Busca la descripción de una clave por su nombre.
pub fn info(name: &str) -> Option<&'static KeyInfo> {
    ALL.iter().copied().find(|k| k.name == name)
}

/// Valor por defecto de una clave.
pub fn default_value(name: &str) -> Option<&'static str> {
    info(name).and_then(|k| k.default)
}

/// `true` si la clave está en la lista de protegidas de Java.
pub fn is_protected(name: &str) -> bool {
    info(name).is_some_and(|k| k.protected)
}

/// Claves que borra cada botón «Restaurar configuración» por pestaña (§4.9.8):
/// `(siempre, solo si no está bloqueado)`.
pub fn tab_restore_keys(section: Section) -> (&'static [&'static str], &'static [&'static str]) {
    match section {
        Section::Pades => (
            &[
                "padesSignReason",
                "padesSignProductionCity",
                "padesSignerContact",
                "padesVisibleSignature",
                "padesObfuscateCertInfo",
                "padesVisibleStamp",
            ],
            &[
                "padesBasicFormat",
                "padesPolicyIdentifier",
                "padesPolicyIdentifierHash",
                "padesPolicyIdentifierHashAlgorithm",
                "padesPolicyQualifier",
                "allowShadowAttack",
                "allowCertifiedPDF",
                "padesCertificationLevel",
            ],
        ),
        Section::Cades => (
            &[],
            &[
                "cadesImplicitMode",
                "cadesMultisign",
                "cadesPolicyIdentifier",
                "cadesPolicyIdentifierHash",
                "cadesPolicyIdentifierHashAlgorithm",
                "cadesPolicyQualifier",
            ],
        ),
        Section::Xades => (
            &[
                "xadesSignatureProductionCity",
                "xadesSignatureProductionProvince",
                "xadesSignatureProductionPostalCode",
                "xadesSignatureProductionCountry",
                "xadesSignerClaimedRole",
            ],
            &[
                "xadesPolicyIdentifier",
                "xadesPolicyIdentifierHash",
                "xadesPolicyIdentifierHashAlgorithm",
                "xadesPolicyQualifier",
                "xadesSignFormat",
                "xadesMultisign",
            ],
        ),
        Section::Facturae => (
            &[
                "facturaeSignerRole",
                "facturaeSignatureProductionCity",
                "facturaeSignatureProductionProvince",
                "facturaeSignatureProductionPostalCode",
                "facturaeSignatureProductionCountry",
            ],
            &[
                "facturaEPolicy",
                "facturaePolicyIdentifier",
                "facturaePolicyIdentifierHash",
                "facturaePolicyIdentifierHashAlgorithm",
                "facturaePolicyQualifier",
            ],
        ),
        Section::Keystores => (
            &[
                "defaultKeystore",
                "useDefaultStoreInBrowserCalls",
                "hideDnieStartScreen",
                "showExpiredCerts",
                "useOnlySignatureCertificates",
                "useOnlyAliasCertificates",
                "skipAuthCertDnie",
            ],
            &[],
        ),
        _ => (&[], &[]),
    }
}

/// Clave de un nodo auxiliar (fuera del nodo principal), §4.2.1.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct AuxKey {
    /// Ruta absoluta del nodo Java.
    pub node: &'static str,
    /// Nombre de la clave.
    pub name: &'static str,
    /// Valor por defecto.
    pub default: Option<&'static str>,
}

/// Fecha de la última comprobación de actualizaciones (`yyyyMMdd`).
pub const AUX_UPDATER_LAST_CHECK: AuxKey = AuxKey {
    node: super::tree::NODE_UPDATER,
    name: "lastCheckDate",
    default: None,
};
/// Último directorio usado en los diálogos de ficheros.
pub const AUX_CURRENT_DIR: AuxKey = AuxKey {
    node: super::tree::NODE_JSE,
    name: "currentDir",
    default: None,
};
/// Última pestaña del diálogo de selección de certificados.
pub const AUX_CERT_VIEW: AuxKey = AuxKey {
    node: super::tree::NODE_CERT_SELECTION,
    name: "certView",
    default: Some("PERSONAL"),
};
/// Recordar el PIN del DNIe durante la sesión.
pub const AUX_USE_CACHE_DNI: AuxKey = AuxKey {
    node: super::tree::NODE_JMULTICARD_UI,
    name: "useCacheDni",
    default: Some("false"),
};
/// Recordar el PIN de CERES durante la sesión.
pub const AUX_USE_CACHE_CERES: AuxKey = AuxKey {
    node: super::tree::NODE_JMULTICARD_UI,
    name: "useCacheCeres",
    default: Some("false"),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nombres_unicos_y_valores_por_defecto_validos() {
        let mut names: Vec<&str> = ALL.iter().map(|k| k.name).collect();
        let n = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), n, "claves duplicadas");
        for k in ALL {
            if let Some(d) = k.default {
                assert!(k.accepts(d), "valor por defecto no válido para {}", k.name);
            }
        }
        assert_eq!(default_value("defaultSignatureFormatOoxml"), Some("CAdES"));
        assert_eq!(default_value("defaultSignatureFormatOdf"), Some("CAdES"));
        assert_eq!(default_value("signatureHashAlgorithm"), Some("SHA256"));
        assert!(
            info("requireSignedPrerefences").is_some(),
            "se conserva la errata"
        );
    }

    #[test]
    fn lista_protegida_de_java() {
        // PreferencesManager.isProtectedPreference (29 claves).
        let java = [
            "checkForUpdates",
            "enabledJmulticard",
            "signatureHashAlgorithm",
            "defaultSignatureFormatPdf",
            "defaultSignatureFormatOoxml",
            "defaultSignatureFormatFacturae",
            "defaultSignatureFormatOdf",
            "defaultSignatureFormatXml",
            "defaultSignatureFormatBin",
            "allowInvalidSignatures",
            "secureConnections",
            "xadesPolicyIdentifier",
            "xadesPolicyIdentifierHash",
            "xadesPolicyIdentifierHashAlgorithm",
            "xadesPolicyQualifier",
            "xadesSignFormat",
            "padesBasicFormat",
            "padesPolicyIdentifier",
            "padesPolicyIdentifierHash",
            "padesPolicyIdentifierHashAlgorithm",
            "padesPolicyQualifier",
            "allowShadowAttack",
            "cadesPolicyIdentifier",
            "cadesPolicyIdentifierHash",
            "cadesPolicyIdentifierHashAlgorithm",
            "cadesPolicyQualifier",
            "cadesImplicitMode",
            "facturaEPolicy",
            "showExpiredCerts",
        ];
        let ours: Vec<&str> = ALL.iter().filter(|k| k.protected).map(|k| k.name).collect();
        assert_eq!(ours.len(), java.len());
        for j in java {
            assert!(is_protected(j), "{j}");
            assert!(info(j).unwrap().lockable);
        }
    }

    #[test]
    fn enumeraciones_tipadas() {
        assert_eq!(
            SignatureFormat::parse_pref("OOXML (Office Open XML)"),
            Some(SignatureFormat::Ooxml)
        );
        assert_eq!(
            MultisignOp::from_pref_lenient("loquesea"),
            MultisignOp::CountersignTree
        );
        assert_eq!(bool::parse_pref("TRUE"), Some(true));
        assert_eq!(bool::parse_pref("1"), None);
        assert_eq!(HashAlgorithm::Sha256.to_pref(), "SHA256");
    }
}
