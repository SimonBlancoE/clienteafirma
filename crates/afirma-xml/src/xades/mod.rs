//! Firmador XAdES (`AOXAdESSigner`): XAdES-BES/EPES (ETSI TS 101 903 1.3.2)
//! y B-Level (EN 319 132-1), en sus variantes Enveloping, Enveloped,
//! Detached (internamente separada) y Externally Detached (incluido el modo
//! Manifest), con cofirma, contrafirma, árbol de firmantes, extracción de
//! datos y sello de tiempo (XAdES-T).

pub mod info;
pub mod multi;
pub mod props;
pub mod sign;
pub mod tsp;

use afirma_core::algorithms::{KeyAlgorithm, SignatureAlgorithm};
use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;
use afirma_core::signer::{CounterSignTarget, SignInfo, Signer, SignersTree};

use crate::dsig::{DsNames, Placeholders, ReferenceSpec, Resolver};
use crate::util::esc_attr;

pub const FORMAT_XADES: &str = "XAdES";
pub const FORMAT_ENVELOPING: &str = "XAdES Enveloping";
pub const FORMAT_ENVELOPED: &str = "XAdES Enveloped";
pub const FORMAT_DETACHED: &str = "XAdES Detached";
pub const FORMAT_EXTERNALLY_DETACHED: &str = "XAdES Externally Detached";

pub const NS_XADES_111: &str = "http://uri.etsi.org/01903/v1.1.1#";
pub const NS_XADES_122: &str = "http://uri.etsi.org/01903/v1.2.2#";
pub const NS_XADES_132: &str = "http://uri.etsi.org/01903/v1.3.2#";
pub const NS_XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";
pub const NS_XADES: &str = "http://uri.etsi.org/01903#";
/// Espacios de nombres de `QualifyingProperties` admitidos por AutoFirma.
pub const SUPPORTED_NAMESPACES: &[&str] = &[NS_XADES, NS_XADES_122, NS_XADES_132, NS_XADES_141];
pub const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
pub const SIGNED_PROPERTIES_TYPES: &[&str] = &[
    "http://uri.etsi.org/01903#SignedProperties",
    "http://uri.etsi.org/01903/v1.2.2#SignedProperties",
    "http://uri.etsi.org/01903/v1.3.2#SignedProperties",
    "http://uri.etsi.org/01903/v1.4.1#SignedProperties",
];
pub const COUNTERSIGNED_TYPE: &str = "http://uri.etsi.org/01903#CountersignedSignature";
pub const DEFAULT_DIGEST_METHOD: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
pub const DEFAULT_SIGN_ALGO: &str = "SHA512withRSA";
pub const XADES_PREFIX: &str = "xades";
pub const DS_PREFIX: &str = "ds";

/// Tabla `XMLConstants.SIGN_ALGOS_URI` (nombre Java exacto -> URI).
pub fn xml_signature_uri(name: &str) -> Option<&'static str> {
    const RSA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    const RSA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const RSA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    const RSA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    const EC1: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    const EC224: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
    const EC256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    const EC384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    const EC512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    Some(match name {
        "SHA1withRSA"
        | "RSA"
        | "SHA-1withRSA"
        | "SHA1withRSAEncryption"
        | "SHA-1withRSAEncryption"
        | "SHAwithRSAEncryption"
        | "SHAwithRSA" => RSA1,
        "SHA256withRSA" | "SHA-256withRSA" | "SHA256withRSAEncryption" | "SHA-256withRSAEncryption" => RSA256,
        "SHA384withRSA" | "SHA-384withRSA" | "SHA384withRSAEncryption" | "SHA-384withRSAEncryption" => RSA384,
        "SHA512withRSA" | "SHA-512withRSA" | "SHA512withRSAEncryption" | "SHA-512withRSAEncryption" => RSA512,
        "SHA1withECDSA"
        | "ECDSA"
        | "SHA-1withECDSA"
        | "SHA1withECDSAEncryption"
        | "SHA-1withECDSAEncryption"
        | "SHAwithECDSAEncryption"
        | "SHAwithECDSA" => EC1,
        "SHA224withECDSA" | "SHA-224withECDSA" | "SHA224withECDSAEncryption" | "SHA-224withECDSAEncryption" => EC224,
        "SHA256withECDSA" | "SHA-256withECDSA" | "SHA256withECDSAEncryption" | "SHA-256withECDSAEncryption" => EC256,
        "SHA384withECDSA" | "SHA-384withECDSA" | "SHA384withECDSAEncryption" | "SHA-384withECDSAEncryption" => EC384,
        "SHA512withECDSA" | "SHA-512withECDSA" | "SHA512withECDSAEncryption" | "SHA-512withECDSAEncryption" => EC512,
        _ => return None,
    })
}

/// Algoritmo de firma XML para el nombre recibido y el tipo de clave.
///
/// Java usa el nombre tal cual (`SIGN_ALGOS_URI`); aquí, si el nombre no
/// corresponde al tipo de la clave (p. ej. `SHA256withRSA` con una clave EC)
/// o es solo una huella (`SHA256`), se compone con el tipo de la clave como
/// hace `AOSignConstants.composeSignatureAlgorithmName` (desviación
/// documentada: en Java la firma fallaría).
pub fn resolve_algorithm(name: &str, key: KeyAlgorithm) -> afirma_core::Result<(String, SignatureAlgorithm)> {
    let unsupported = || {
        AfirmaError::new(
            codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            format!("Los formatos de firma XML no soportan el algoritmo de firma {name}"),
        )
    };
    if let Some(uri) = xml_signature_uri(name) {
        let alg = SignatureAlgorithm::from_xml_uri(uri).ok_or_else(unsupported)?;
        if alg.key == key {
            return Ok((uri.to_string(), alg));
        }
    }
    if key == KeyAlgorithm::Dsa {
        return Err(unsupported());
    }
    let alg = afirma_core::algorithms::compose_signature_algorithm(name, key).map_err(|_| unsupported())?;
    let uri = xml_signature_uri(&alg.java_name()).ok_or_else(unsupported)?;
    Ok((uri.to_string(), alg))
}

/// Nombre canónico de un formato XAdES validado sin distinguir mayúsculas.
///
/// Java valida sin distinguir mayúsculas pero después compara con `equals`,
/// de modo que `xades enveloping` produce una firma sin datos; aquí se
/// normaliza (desviación documentada).
pub fn canonical_format(f: &str) -> Option<&'static str> {
    [
        FORMAT_ENVELOPING,
        FORMAT_ENVELOPED,
        FORMAT_DETACHED,
        FORMAT_EXTERNALLY_DETACHED,
    ]
    .into_iter()
    .find(|c| c.eq_ignore_ascii_case(f.trim()))
}

/// Espacio de nombres compatible con el perfil baseline.
pub fn is_baseline_compatible(ns: &str) -> bool {
    ns == NS_XADES_132 || ns == NS_XADES_141
}

/// Elementos de una firma XAdES a generar.
pub(crate) struct Assembly {
    pub ds: DsNames,
    pub xades_prefix: String,
    pub xades_ns: String,
    /// Prefijo de los identificadores (`Signature-<uuid>`).
    pub sig_prefix: String,
    pub c14n_uri: String,
    pub sig_method_uri: String,
    pub digest_uri: String,
    pub signed_props_type: String,
    pub data_refs: Vec<ReferenceSpec>,
    /// Objetos (`ds:Object` completos) añadidos antes de las propiedades.
    pub objects_before: Vec<String>,
    pub props: props::SignedProps,
    /// `KeyInfo` completo.
    pub key_info: String,
    pub keyinfo_reference: bool,
    /// El prefijo XMLDSig ya está declarado en el punto de inserción (solo
    /// cambia el orden de atributos de `Signature`).
    pub ds_in_scope: bool,
    pub xades_in_scope: bool,
}

impl Assembly {
    pub fn signature_id(&self) -> String {
        format!("{}-Signature", self.sig_prefix)
    }

    /// Texto de la firma con marcadores.
    pub fn render(&self, ph: &mut Placeholders) -> String {
        let ds = &self.ds;
        let mut refs = self.data_refs.clone();
        let mut sp = ReferenceSpec::new(format!("#{}-SignedProperties", self.sig_prefix), &self.digest_uri);
        sp.ty = Some(self.signed_props_type.clone());
        refs.push(sp);
        if self.keyinfo_reference {
            refs.push(ReferenceSpec::new(
                format!("#{}-KeyInfo", self.sig_prefix),
                &self.digest_uri,
            ));
        }
        let mut s = String::new();
        let id_attr = format!("Id=\"{}\"", esc_attr(&self.signature_id()));
        if self.ds_in_scope {
            s.push_str(&format!("<{} {id_attr}{}>", ds.q("Signature"), ds.xmlns()));
        } else {
            s.push_str(&format!("<{}{} {id_attr}>", ds.q("Signature"), ds.xmlns()));
        }
        s.push_str(&crate::dsig::render_signed_info(
            ds,
            &self.c14n_uri,
            &self.sig_method_uri,
            &refs,
            ph,
        ));
        s.push_str(&format!(
            "<{sv} Id=\"{}-SignatureValue\">{}</{sv}>",
            self.sig_prefix,
            ph.signature_value(),
            sv = ds.q("SignatureValue")
        ));
        s.push_str(&self.key_info);
        for o in &self.objects_before {
            s.push_str(o);
        }
        s.push_str(&props::render_qualifying_object(
            ds,
            &self.xades_prefix,
            &self.xades_ns,
            &self.sig_prefix,
            &self.props,
            self.xades_in_scope,
        ));
        s.push_str(&format!("</{}>", ds.q("Signature")));
        s
    }
}

/// Firmador XAdES.
#[derive(Default)]
pub struct XadesSigner {
    resolver: Option<std::sync::Arc<dyn Resolver + Send + Sync>>,
}

impl XadesSigner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Instala un resolutor de URI para las referencias externas
    /// (`setUriDereferencer`, usado por ASiC-S).
    pub fn with_resolver(resolver: std::sync::Arc<dyn Resolver + Send + Sync>) -> Self {
        XadesSigner {
            resolver: Some(resolver),
        }
    }

    fn resolver(&self) -> &dyn Resolver {
        match &self.resolver {
            Some(r) => r.as_ref(),
            None => &crate::dsig::NoResolver,
        }
    }

    /// Firma con datos opcionales (Externally Detached admite `None`).
    pub fn sign_optional(
        &self,
        data: Option<&[u8]>,
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        let signed = sign::sign(data, algorithm, key, extra, self.resolver())?;
        tsp::timestamp_if_requested(signed, extra)
    }

    /// `needData`: los datos son opcionales al firmar en modo Externally
    /// Detached o con Manifest.
    pub fn need_data(operation: &str, config: Option<&ExtraParams>) -> bool {
        info::is_data_mandatory(operation, config)
    }
}

impl Signer for XadesSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_XADES
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        self.sign_optional(Some(data), algorithm, key, extra)
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        multi::cosign(sign, algorithm, key, extra, self.resolver())
    }

    fn countersign(
        &self,
        sign: &[u8],
        algorithm: &str,
        target: &CounterSignTarget,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        multi::countersign(sign, algorithm, target, key, extra)
    }

    fn signers_structure(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignersTree> {
        info::signers_structure(sign)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        info::is_sign(data)
    }

    fn is_valid_data_file(&self, _data: &[u8]) -> bool {
        true
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        format!("{}{}.xsig", original.unwrap_or("null"), in_text.unwrap_or(""))
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        info::get_data(sign)
    }

    fn sign_info(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        info::sign_info(sign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_table() {
        assert_eq!(
            resolve_algorithm("SHA256withRSA", KeyAlgorithm::Rsa).unwrap().0,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        );
        assert_eq!(
            resolve_algorithm("RSA", KeyAlgorithm::Rsa).unwrap().0,
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        );
        assert_eq!(
            resolve_algorithm("SHA256withRSA", KeyAlgorithm::Ec).unwrap().0,
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        );
        assert!(resolve_algorithm("SHA1withDSA", KeyAlgorithm::Dsa).is_err());
        assert_eq!(canonical_format("xades enveloping"), Some(FORMAT_ENVELOPING));
    }
}
