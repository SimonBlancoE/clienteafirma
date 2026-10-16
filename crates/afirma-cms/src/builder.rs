//! API para otros formatos (PAdES, firma trifásica, lotes): construcción de
//! un `SignedData` CAdES/CMS separado a partir de una huella calculada
//! externamente, con control sobre los atributos que se incluyen.
//!
//! El flujo en dos pasos permite firmar fuera del proceso (trifásica):
//! 1. [`SignedDataBuilder::signed_attributes`]: DER (`SET OF`) de los
//!    atributos firmados, que es lo que se firma con la clave.
//! 2. [`SignedDataBuilder::assemble`]: compone el `SignedData` final con los
//!    atributos y el valor PKCS#1/ECDSA.

use afirma_core::algorithms::SignatureAlgorithm;
use afirma_core::error::AfirmaError;
use afirma_core::{ExtraParams, SigningKey};
use chrono::{DateTime, Utc};

use crate::cades::{CadesParameters, attrs};
use crate::cert::CertView;
use crate::cms::{self, SignedDataParts, encode_signer_info};
use crate::{alg, pkcs1, tsp};

/// OID que se escribe en `signatureAlgorithm` del SignerInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgorithmOid {
    /// `rsaEncryption` para RSA (como la firma CAdES/CMS de AutoFirma) y el
    /// OID completo para ECDSA/DSA.
    #[default]
    RsaEncryption,
    /// OID completo del algoritmo (`sha256WithRSAEncryption`...), como en las
    /// cofirmas y contrafirmas CAdES.
    Full,
}

/// Constructor de `SignedData` CAdES.
#[derive(Debug, Clone)]
pub struct SignedDataBuilder {
    /// Configuración CAdES (todos los campos son públicos y modificables:
    /// `signing_time`, `signing_certificate_v2`, `external_policy`,
    /// `content_type_oid`/`content_description` para `contentHints`...).
    pub params: CadesParameters,
    pub algorithm: SignatureAlgorithm,
    /// Cadena de certificados (el primero es el del firmante).
    pub cert_chain: Vec<Vec<u8>>,
    /// Certificados que se incluyen en el `SignedData` (por defecto la cadena
    /// completa, o solo el del firmante con `includeOnlySignningCertificate`).
    pub certificates: Vec<Vec<u8>>,
    pub signature_algorithm_oid: SignatureAlgorithmOid,
    /// Incluir el atributo `contentType` (siempre en CAdES salvo contrafirmas).
    pub include_content_type: bool,
    /// Atributos firmados adicionales (cada uno codificado como `Attribute`).
    pub extra_signed_attributes: Vec<Vec<u8>>,
    /// Atributos no firmados (cada uno codificado como `Attribute`).
    pub unsigned_attributes: Vec<Vec<u8>>,
    /// Contenido a incrustar (`None` = firma separada).
    pub content: Option<Vec<u8>>,
}

impl SignedDataBuilder {
    /// Configuración para una huella del contenido ya calculada con la
    /// huella de `algorithm` (p. ej. la de los rangos de bytes de un PDF).
    /// Los `extraParams` CAdES se interpretan igual que en una firma
    /// (`policyIdentifier`, `signerClaimedRoles`, `includeSigningTimeAttribute`,
    /// `includeContentHintAttribute`, `signingCertificateV2`...).
    pub fn for_digest(
        content_digest: &[u8],
        algorithm: SignatureAlgorithm,
        cert_chain: Vec<Vec<u8>>,
        extra: &ExtraParams,
        now: DateTime<Utc>,
    ) -> afirma_core::Result<Self> {
        if cert_chain.is_empty() {
            return Err(AfirmaError::invalid_argument(
                "La cadena de certificados debe contener al menos un elemento",
            ));
        }
        let mut params = CadesParameters::load(None, None, &algorithm.java_name(), extra, now)?;
        params.data_digest = Some(content_digest.to_vec());
        params.content_data = None;
        let certificates = if params.included_only_signing_certificate {
            vec![cert_chain[0].clone()]
        } else {
            cert_chain.clone()
        };
        Ok(SignedDataBuilder {
            params,
            algorithm,
            cert_chain,
            certificates,
            signature_algorithm_oid: SignatureAlgorithmOid::RsaEncryption,
            include_content_type: true,
            extra_signed_attributes: Vec::new(),
            unsigned_attributes: Vec::new(),
            content: None,
        })
    }

    /// Configuración del CMS de una firma PAdES (`PAdESTriPhaseSigner.preSign`,
    /// especificación 04 §6): huella de los rangos del PDF, sin `signingTime`
    /// (la fecha va en `/M`), sin `contentHints` y sin `signerLocation`; el
    /// resto de atributos según los `extraParams` (política, compromisos,
    /// roles, `mimeType`, `signingCertificateV2`...).
    pub fn for_pades(
        range_digest: &[u8],
        algorithm: SignatureAlgorithm,
        cert_chain: Vec<Vec<u8>>,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Self> {
        let mut b = Self::for_digest(range_digest, algorithm, cert_chain, extra, chrono::Utc::now())?;
        b.params.signer_location = None;
        b.params.content_type_oid = None;
        b.params.content_description = None;
        b.params.signing_time = None;
        Ok(b)
    }

    fn signer_cert(&self) -> afirma_core::Result<&[u8]> {
        self.cert_chain.first().map(Vec::as_slice).ok_or_else(|| {
            AfirmaError::invalid_argument("La cadena de certificados debe contener al menos un elemento")
        })
    }

    /// Atributos firmados como `SET OF` DER: los datos que hay que firmar.
    pub fn signed_attributes(&self) -> afirma_core::Result<Vec<u8>> {
        let mut list = attrs::generate_signed_attributes(self.signer_cert()?, &self.params, false)?;
        if !self.include_content_type {
            list.retain(|a| {
                crate::asn1::Tlv::parse_single(a)
                    .ok()
                    .and_then(|t| cms::Attribute::parse(t).ok())
                    .is_none_or(|attr| !attr.is(crate::oids::CONTENT_TYPE))
            });
        }
        list.extend(self.extra_signed_attributes.iter().cloned());
        Ok(attrs::attributes_set(&list))
    }

    /// Compone el `ContentInfo` final con los atributos firmados devueltos
    /// por [`Self::signed_attributes`] y el valor de firma.
    pub fn assemble(&self, signed_attributes: &[u8], signature_value: &[u8]) -> afirma_core::Result<Vec<u8>> {
        let cert0 = CertView::parse(self.signer_cert()?)
            .map_err(|e| AfirmaError::invalid_argument(format!("Certificado de firma no valido: {e}")))?;
        let sig_oid = match self.signature_algorithm_oid {
            SignatureAlgorithmOid::RsaEncryption => alg::sign_signature_alg_oid(self.algorithm),
            SignatureAlgorithmOid::Full => alg::signature_oid(self.algorithm),
        };
        let digest_alg_id = alg::digest_alg_id(self.algorithm.digest);
        let unsigned = (!self.unsigned_attributes.is_empty()).then_some(self.unsigned_attributes.as_slice());
        let si = encode_signer_info(
            &cert0.issuer_and_serial(),
            &digest_alg_id,
            Some(signed_attributes),
            &alg::alg_id_null(sig_oid),
            signature_value,
            unsigned,
        );
        Ok(SignedDataParts {
            digest_algorithms: vec![digest_alg_id],
            encap_content_info: cms::encap_content_info(self.content.as_deref()),
            certificates: Some(self.certificates.clone()),
            crls: None,
            signer_infos: vec![si],
        }
        .encode())
    }

    /// Firma con la clave (con autoverificación) y compone el resultado.
    pub fn sign(&self, key: &dyn SigningKey) -> afirma_core::Result<Vec<u8>> {
        let tbs = self.signed_attributes()?;
        let sig = pkcs1::sign(key, &tbs, self.algorithm, Some(self.signer_cert()?))?;
        self.assemble(&tbs, &sig)
    }

    /// Firma y añade un sello de tiempo de firma (CAdES-T / PAdES-T) con los
    /// parámetros de la TSA.
    pub fn sign_with_timestamp(&self, key: &dyn SigningKey, tsa: &tsp::Timestamper) -> afirma_core::Result<Vec<u8>> {
        tsa.add_timestamp(&self.sign(key)?)
    }
}
