//! Firmas CAdES: firma, cofirma y contrafirma (`AOCAdESSigner`,
//! `AOCAdESCoSigner`, `AOCAdESCounterSigner`).

pub mod attrs;
pub mod params;
pub mod policy;

use afirma_core::algorithms::{SignatureAlgorithm, compose_signature_algorithm};
use afirma_core::error::{AfirmaError, ConfirmEffect, ErrorKind, codes};
use afirma_core::{CounterSignTarget, ExtraParams, SignInfo, Signer, SignersTree, SigningKey};
use chrono::{DateTime, SubsecRound, Utc};

pub use params::{CadesParameters, Profile};

use crate::alg;
use crate::cert::CertView;
use crate::cms::{self, SignedData, SignedDataParts, SignerInfo, encode_signer_info, to_der_preserving};
use crate::{detect, oids, pkcs1, tree, tsp};

/// Nombre del formato.
pub const FORMAT_CADES: &str = "CAdES";

/// Atributos no firmados de firmas longevas que impiden multifirmar sin
/// confirmación (`CAdESMultiUtil.LONG_TERM_ATTRIBUTES`).
pub const LONG_TERM_ATTRIBUTES: [&str; 4] =
    [oids::ARCHIVE_TIMESTAMP_V2, oids::ARCHIVE_TIMESTAMP_V3, oids::LONG_TERM_VALIDATION, oids::ARCHIVE_TIMESTAMP];

/// Instante actual truncado a segundos (precisión del `signingTime`).
pub fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(0)
}

/// Error `SigningLTSException`: la firma tiene atributos longevos y hay que
/// confirmar con `allowSignLTSignature=true`.
pub fn signing_lts_error(oid: &str, denied: bool) -> AfirmaError {
    let mut e = AfirmaError::needs_confirmation(
        codes::SIGNING_LTS,
        format!("No se permite la multifirma de firmas con atributos longevos (encontrado OID={oid})"),
        "signingLts",
        "allowSignLTSignature",
        ConfirmEffect::SetParamTrue,
    );
    if let ErrorKind::NeedsIntervention { denied: d, .. } = &mut e.kind {
        *d = denied;
    }
    e
}

fn lts_check_enabled(params: &ExtraParams) -> (bool, bool) {
    let allow = params.get("allowSignLTSignature");
    let check = !allow.is_some_and(|v| v.eq_ignore_ascii_case("true"));
    (check, allow.is_some())
}

/// `CAdESMultiUtil.checkLongTermAttributes`: comprueba los firmantes de
/// primer nivel.
pub fn check_long_term_attributes(sign: &[u8], params: &ExtraParams) -> afirma_core::Result<()> {
    let (check, denied) = lts_check_enabled(params);
    if !check {
        return Ok(());
    }
    let sd = SignedData::parse(sign).map_err(|e| {
        AfirmaError::invalid_signature_format(format!("La firma proporcionada no es un SignedData compatible CMS: {e}"))
    })?;
    for si in &sd.signer_infos {
        for oid in LONG_TERM_ATTRIBUTES {
            if si.has_unsigned_attr(oid) {
                return Err(signing_lts_error(oid, denied));
            }
        }
    }
    Ok(())
}

/// Comprobaciones previas del algoritmo (`AOCAdESSigner.checkAlgorithm`) y
/// composición con el tipo de la clave.
pub fn resolve_algorithm(
    algorithm: &str,
    key: &dyn SigningKey,
    params: &ExtraParams,
) -> afirma_core::Result<SignatureAlgorithm> {
    if algorithm.is_empty() {
        return Err(AfirmaError::invalid_argument("El algoritmo de firma no puede ser nulo"));
    }
    if algorithm.to_uppercase().starts_with("MD") {
        return Err(AfirmaError::new(
            codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            "CAdES no permite huellas digitales MD2 o MD5 (Decision 130/2011 CE)",
        ));
    }
    if params.get("profile").is_some_and(|p| p.eq_ignore_ascii_case("baseline"))
        && alg::is_sha1_signature_algorithm(algorithm)
    {
        tracing::warn!(
            "El algoritmo '{algorithm}' no esta recomendado para su uso en las firmas baseline por no cumplir los requisitos de seguridad actuales"
        );
    }
    compose_signature_algorithm(algorithm, key.key_algorithm())
}

fn chain_of(key: &dyn SigningKey) -> afirma_core::Result<Vec<Vec<u8>>> {
    let chain = key.certificate_chain();
    if chain.is_empty() {
        return Err(AfirmaError::invalid_argument("La cadena de certificados debe contener al menos un elemento"));
    }
    Ok(chain)
}

fn cert_view(der: &[u8]) -> afirma_core::Result<CertView<'_>> {
    CertView::parse(der).map_err(|e| {
        AfirmaError::new(codes::ENCODING_SIGNING_CERTIFICATE, format!("Certificado de firma no valido: {e}"))
    })
}

/// Prefirma: atributos firmados codificados como `SET OF` DER (los datos que
/// se firman con la clave; `CAdESTriPhaseSigner.preSign`).
pub fn pre_sign(signer_cert: &[u8], cfg: &CadesParameters) -> afirma_core::Result<Vec<u8>> {
    let attrs = attrs::generate_signed_attributes(signer_cert, cfg, false).map_err(|e| match e.kind {
        ErrorKind::InvalidArgument => AfirmaError::new(
            codes::INTERNAL_BINARY_SIGNING_ERROR,
            format!("Error obteniendo los atributos a firmar: {e}"),
        ),
        _ => e,
    })?;
    Ok(attrs::attributes_set(&attrs))
}

/// Postfirma: compone el `SignedData` CAdES a partir de los atributos
/// firmados (`pre_sign`) y del valor de firma (`CAdESTriPhaseSigner.postSign`).
///
/// `content` son los datos a incrustar (firma implícita) o `None`.
pub fn post_sign(
    alg: SignatureAlgorithm,
    content: Option<&[u8]>,
    cert_chain: &[Vec<u8>],
    signature_value: &[u8],
    signed_attributes: &[u8],
) -> afirma_core::Result<Vec<u8>> {
    let cert0 = cert_view(cert_chain.first().ok_or_else(|| {
        AfirmaError::invalid_argument("La cadena de certificados debe contener al menos una entrada")
    })?)?;
    let digest_alg_id = alg::digest_alg_id(alg.digest);
    let si = encode_signer_info(
        &cert0.issuer_and_serial(),
        &digest_alg_id,
        Some(signed_attributes),
        &alg::alg_id_null(alg::sign_signature_alg_oid(alg)),
        signature_value,
        None,
    );
    let certificates: Vec<Vec<u8>> = cert_chain
        .iter()
        .filter(|c| {
            let ok = CertView::parse(c).is_ok();
            if !ok {
                tracing::error!("Error insertando un certificado en la cadena de confianza");
            }
            ok
        })
        .cloned()
        .collect();
    Ok(SignedDataParts {
        digest_algorithms: vec![digest_alg_id],
        encap_content_info: cms::encap_content_info(content),
        certificates: Some(certificates),
        crls: None,
        signer_infos: vec![si],
    }
    .encode())
}

/// Firma CAdES con un instante de firma dado (`AOCAdESSigner.sign`).
pub fn sign_at(
    data: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
    now: DateTime<Utc>,
) -> afirma_core::Result<Vec<u8>> {
    let chain = chain_of(key)?;
    let mut params = extra.clone();
    let sig_alg = resolve_algorithm(algorithm, key, &params)?;
    let alg_name = sig_alg.java_name();
    // noticeIncompatibleConfig
    if params.contains("precalculatedHashAlgorithm") && params.contains("mode") {
        tracing::warn!(
            "Se ignorara el parametro 'mode' por haberse proporcionado tambien el parametro 'precalculatedHashAlgorithm'. La firma sera explicita."
        );
        params.remove("mode");
    }
    if alg::is_sha2_signature_algorithm(&alg_name) && params.contains("signingCertificateV2") {
        tracing::warn!(
            "Se ignorara la propiedad 'signingCertificateV2' porque las firmas SHA2 siempre usan SigningCertificateV2"
        );
        params.remove("signingCertificateV2");
    }
    let cfg = CadesParameters::load(Some(data), None, &alg_name, &params, now)?;
    let chain: Vec<Vec<u8>> = if cfg.included_only_signing_certificate { vec![chain[0].clone()] } else { chain };
    let pre = pre_sign(&chain[0], &cfg)?;
    let sig = pkcs1::sign(key, &pre, sig_alg, Some(&chain[0]))?;
    let signature = post_sign(sig_alg, cfg.content_data.as_deref(), &chain, &sig, &pre)?;
    // CAdES-T: en Java esta rama nunca llega a ejecutarse (fallo de reflexión);
    // aquí se aplica el sello cuando se indica `tsaURL`.
    match tsp::TsaParams::from_extra_params(&params)? {
        Some(tsa) => tsp::Timestamper::new(tsa).add_timestamp(&signature),
        None => Ok(signature),
    }
}

fn recode_multisign(e: AfirmaError) -> AfirmaError {
    if e.code == Some(codes::INTERNAL_BINARY_SIGNING_ERROR)
        || (e.code.is_none() && e.kind == ErrorKind::InvalidArgument)
    {
        AfirmaError::new(
            codes::UNKWNON_BINARY_SIGNING_ERROR,
            format!("Error generando la multifirma CAdES: {}", e.message),
        )
    } else {
        e
    }
}

/// Cofirma CAdES (`AOCAdESCoSigner.cosign`). `data` son los datos firmados
/// (necesarios si la firma es explícita y ningún firmante usa la misma huella).
pub fn cosign_at(
    data: Option<&[u8]>,
    sign: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
    now: DateTime<Utc>,
) -> afirma_core::Result<Vec<u8>> {
    let chain = chain_of(key)?;
    let mut params = extra.clone();
    let sig_alg = resolve_algorithm(algorithm, key, &params)?;
    let alg_name = sig_alg.java_name();
    check_long_term_attributes(sign, &params)?;
    if params.contains("precalculatedHashAlgorithm") {
        tracing::warn!(
            "Se ignorara el parametro 'mode' por haberse proporcionado tambien el parametro 'precalculatedHashAlgorithm'. La firma sera explicita."
        );
        params.remove("mode");
    }
    if alg::is_sha2_signature_algorithm(&alg_name) && params.contains("signingCertificateV2") {
        params.remove("signingCertificateV2");
    }
    let sd = SignedData::parse(sign)
        .map_err(|e| AfirmaError::invalid_signature_format(format!("La firma proporcionada no es CMS/CAdES: {e}")))?;
    let mut cfg = CadesParameters::load(data, Some(&sd), &alg_name, &params, now)?;

    // encapContentInfo
    let encap = match &cfg.content_data {
        Some(c) => cms::encap_content_info(Some(c)),
        None => {
            if cfg.data_digest.is_none()
                && let Some(content) = sd.content() {
                    cfg.data_digest = Some(cfg.digest_algorithm.digest(&content));
                }
            to_der_preserving(&sd.encap_content_info)
        }
    };

    // Certificados: los existentes más toda la cadena del firmante.
    let mut certificates = sd.certificates.as_ref().map(cms::set_elements_der).unwrap_or_default();
    certificates.extend(chain.iter().cloned());

    // Huella de un firmante con el mismo algoritmo si no hay datos.
    let digest_oid = sig_alg.digest.oid();
    let mut signer_infos = Vec::new();
    for si in &sd.signer_infos {
        signer_infos.push(to_der_preserving(&si.raw));
        if cfg.data_digest.is_none() && si.digest_oid.is(digest_oid)
            && let Some(md) = si.message_digest() {
                cfg.data_digest = Some(md);
            }
    }
    if cfg.data_digest.is_none() && cfg.content_data.is_none() {
        return Err(AfirmaError::new(
            codes::SIGNATURE_DOESNT_CONTAIN_DATA,
            "No se puede crear la cofirma ya que no se han encontrado ni los datos firmados ni una huella digital compatible con el algoritmo de firma",
        ));
    }

    let cert0 = cert_view(&chain[0])?;
    let signed_attrs =
        attrs::attributes_set(&attrs::generate_signed_attributes(&chain[0], &cfg, false).map_err(recode_multisign)?);
    let sig = pkcs1::sign(key, &signed_attrs, sig_alg, Some(&chain[0]))?;
    let cert_key = cert0
        .key_algorithm()
        .ok_or_else(|| AfirmaError::invalid_argument("Tipo de clave del certificado no soportado"))?;
    signer_infos.push(encode_signer_info(
        &cert0.issuer_and_serial(),
        &alg::digest_alg_id(sig_alg.digest),
        Some(&signed_attrs),
        &alg::alg_id_null(alg::multisign_signature_alg_oid(sig_alg.digest, cert_key)),
        &sig,
        None,
    ));

    Ok(SignedDataParts {
        digest_algorithms: cms::digest_algorithms_with(&sd.digest_algorithms, &alg::digest_alg_id(sig_alg.digest)),
        encap_content_info: encap,
        certificates: Some(certificates),
        crls: sd.crls.as_ref().map(cms::set_elements_der),
        signer_infos,
    }
    .encode())
}

struct CounterSignCtx<'k> {
    key: &'k dyn SigningKey,
    chain: Vec<Vec<u8>>,
    sig_alg: SignatureAlgorithm,
    cfg: CadesParameters,
    tree: bool,
    check_lts: bool,
    lts_denied: bool,
}

impl CounterSignCtx<'_> {
    fn new_countersignature(&mut self, target: &SignerInfo<'_>) -> afirma_core::Result<Vec<u8>> {
        self.cfg.content_data = Some(target.signature_value());
        self.cfg.data_digest = None;
        match self.cfg.profile {
            Profile::Advanced => {
                self.cfg.content_type_oid = Some(oids::DATA.to_string());
                self.cfg.content_description = None;
            }
            Profile::Baseline => {
                self.cfg.content_type_oid = None;
                self.cfg.content_description = None;
            }
        }
        let signed_attrs = attrs::attributes_set(
            &attrs::generate_signed_attributes(&self.chain[0], &self.cfg, true).map_err(recode_multisign)?,
        );
        let sig = pkcs1::sign(self.key, &signed_attrs, self.sig_alg, Some(&self.chain[0]))?;
        let cert0 = cert_view(&self.chain[0])?;
        let cert_key = cert0
            .key_algorithm()
            .ok_or_else(|| AfirmaError::invalid_argument("Tipo de clave del certificado no soportado"))?;
        Ok(encode_signer_info(
            &cert0.issuer_and_serial(),
            &alg::digest_alg_id(self.sig_alg.digest),
            Some(&signed_attrs),
            &alg::alg_id_null(alg::multisign_signature_alg_oid(self.sig_alg.digest, cert_key)),
            &sig,
            None,
        ))
    }

    fn process(&mut self, si: &SignerInfo<'_>) -> afirma_core::Result<Vec<u8>> {
        let mut kept = Vec::new();
        let mut children = Vec::new();
        let mut is_leaf = true;
        let unsigned = si.unsigned_attributes().map_err(|e| {
            AfirmaError::new(codes::UNKWNON_BINARY_SIGNING_ERROR, format!("Atributos no firmados no validos: {e}"))
        })?;
        for ua in &unsigned {
            if self.check_lts
                && let Some(oid) = LONG_TERM_ATTRIBUTES.iter().find(|o| ua.is(o)) {
                    return Err(signing_lts_error(oid, self.lts_denied));
                }
            if ua.is(oids::COUNTER_SIGNATURE) {
                is_leaf = false;
                for v in &ua.values {
                    // Los valores que no son SignerInfo se descartan, como en AutoFirma.
                    if let Ok(child) = SignerInfo::parse(*v) {
                        children.push(self.process(&child)?);
                    }
                }
            } else {
                kept.push(to_der_preserving(&ua.raw));
            }
        }
        if self.tree || is_leaf {
            children.push(self.new_countersignature(si)?);
        }
        kept.push(cms::encode_attribute(oids::COUNTER_SIGNATURE, &children));
        Ok(cms::rebuild_signer_info(si, Some(&kept)))
    }
}

/// Contrafirma CAdES (`AOCAdESCounterSigner.countersign`). Solo admite
/// `TREE` y `LEAFS`.
pub fn countersign_at(
    sign: &[u8],
    algorithm: &str,
    target: &CounterSignTarget,
    key: &dyn SigningKey,
    extra: &ExtraParams,
    now: DateTime<Utc>,
) -> afirma_core::Result<Vec<u8>> {
    let chain = chain_of(key)?;
    let params = extra.clone();
    let sig_alg = resolve_algorithm(algorithm, key, &params)?;
    let alg_name = sig_alg.java_name();
    check_long_term_attributes(sign, &params)?;
    let cfg = CadesParameters::load(None, None, &alg_name, &params, now)?;
    let tree = match target {
        CounterSignTarget::Tree => true,
        CounterSignTarget::Leafs => false,
        CounterSignTarget::Nodes(_) | CounterSignTarget::Signers(_) => {
            return Err(AfirmaError::new(
                codes::UNSUPPORTED_COUNTERSIGN_CONFIG,
                "No se soporta la firma de nodos individuales",
            ));
        }
    };
    let sd = SignedData::parse(sign).map_err(|e| {
        AfirmaError::invalid_signature_format(format!(
            "No se ha encontrado un SignedData en los datos a contrafirmar: {e}"
        ))
    })?;
    let mut certificates = sd.certificates.as_ref().map(cms::set_elements_der).unwrap_or_default();
    certificates.extend(chain.iter().cloned());
    let (check_lts, lts_denied) = lts_check_enabled(&params);
    let mut ctx = CounterSignCtx { key, chain, sig_alg, cfg, tree, check_lts, lts_denied };
    let mut signer_infos = Vec::new();
    for si in &sd.signer_infos {
        signer_infos.push(ctx.process(si)?);
    }
    Ok(SignedDataParts {
        digest_algorithms: cms::set_elements_der(&sd.digest_algorithms),
        encap_content_info: to_der_preserving(&sd.encap_content_info),
        certificates: Some(certificates),
        crls: sd.crls.as_ref().map(cms::set_elements_der),
        signer_infos,
    }
    .encode())
}

/// Firmador CAdES (`AOCAdESSigner`).
#[derive(Debug, Clone, Copy, Default)]
pub struct CadesSigner;

/// `getSignedName` común a CMS/CAdES: `nombre + inText + extensión`.
pub fn signed_name_with(original: Option<&str>, in_text: Option<&str>, ext: &str) -> String {
    format!("{}{}{ext}", original.unwrap_or("null"), in_text.unwrap_or(""))
}

impl Signer for CadesSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_CADES
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        sign_at(data, algorithm, key, extra, now())
    }

    fn cosign(
        &self,
        data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        cosign_at(data, sign, algorithm, key, extra, now())
    }

    fn countersign(
        &self,
        sign: &[u8],
        algorithm: &str,
        target: &CounterSignTarget,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        countersign_at(sign, algorithm, target, key, extra, now())
    }

    fn signers_structure(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignersTree> {
        if !detect::is_cades_valid(sign, false) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un objeto de firma CAdES",
            ));
        }
        tree::read_signers_tree(sign)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        detect::is_cades_signed_data(data, true)
    }

    fn is_valid_data_file(&self, _data: &[u8]) -> bool {
        true
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        signed_name_with(original, in_text, ".csig")
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        if !detect::is_cades_valid(sign, false) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un objeto de firma",
            ));
        }
        detect::obtain_data(sign)
    }

    fn sign_info(&self, sign: &[u8], params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        if !self.is_sign(sign, params) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un objeto de firma",
            ));
        }
        Ok(SignInfo { format: FORMAT_CADES.to_string(), ..Default::default() })
    }
}
