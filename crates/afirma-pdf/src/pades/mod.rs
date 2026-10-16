//! Firmador PAdES (`AOPDFSigner`): formatos `PAdES` y `Adobe PDF`.

pub mod errors;
pub mod params;
pub mod prepare;

use std::sync::Arc;

use afirma_core::algorithms::compose_signature_algorithm;
use afirma_core::error::codes;
use afirma_core::{
    AfirmaError, CounterSignTarget, DigestAlgorithm, ExtraParams, SignInfo, SignatureAlgorithm,
    Signer, SignerNode, SignersTree, SigningKey, SimpleSignInfo,
};

use crate::cms::{self, CommitmentType, SigPolicy, SignedAttrsConfig};
use crate::pdf::date::{SignTime, millis, now, parse_pdf_date, parse_sign_time};
use crate::pdf::doc::{PdfDoc, has_pdf_header};
use crate::tsp::{DefaultTransport, SharedTransport, Timestamper, TsaParams, TsaTransport};
use params::*;
use prepare::{PrepareInput, Prepared, SigKind, prepare};

/// Nombre de formato `PAdES`.
pub const FORMAT_PADES: &str = "PAdES";
/// Nombre de formato `Adobe PDF`.
pub const FORMAT_PDF: &str = "Adobe PDF";
/// Algoritmo por defecto.
pub const DEFAULT_ALGORITHM: &str = "SHA512withRSA";
/// Tamaño mínimo de un PDF (`PDF_MIN_FILE_SIZE`).
pub const PDF_MIN_FILE_SIZE: usize = 70;

/// Post-procesado opcional del CMS (`SignEnhancer`).
pub trait SignEnhancer: Send + Sync {
    fn enhance(&self, cms: &[u8], params: &ExtraParams) -> Result<Vec<u8>, AfirmaError>;
}

/// Firmador PAdES.
#[derive(Clone)]
pub struct PadesSigner {
    format: &'static str,
    secure_mode: bool,
    transport: Arc<dyn TsaTransport>,
    enhancer: Option<Arc<dyn SignEnhancer>>,
}

impl Default for PadesSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Resultado de la prefirma PAdES.
#[derive(Debug, Clone)]
pub struct PadesPreSign {
    /// PDF con la revisión de firma y `/Contents` vacío.
    pub prepared: Prepared,
    /// Atributos firmados (DER, `SET OF`): lo que se firma con la clave.
    pub signed_attributes: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
    pub chain: Vec<Vec<u8>>,
    pub sign_time: SignTime,
    /// Constructor del CMS (`afirma-cms`) con la configuración de la firma.
    pub builder: afirma_cms::SignedDataBuilder,
}

impl PadesSigner {
    /// Firmador con el nombre de formato `PAdES` (modo seguro activado).
    pub fn new() -> Self {
        PadesSigner {
            format: FORMAT_PADES,
            secure_mode: true,
            transport: Arc::new(DefaultTransport),
            enhancer: None,
        }
    }

    /// Firmador con el nombre de formato `Adobe PDF`.
    pub fn adobe_pdf() -> Self {
        PadesSigner {
            format: FORMAT_PDF,
            ..Self::new()
        }
    }

    /// Modo seguro (`setSecureMode`): sin él, las imágenes y adjuntos pueden
    /// ser rutas de fichero.
    pub fn with_secure_mode(mut self, secure: bool) -> Self {
        self.secure_mode = secure;
        self
    }

    pub fn secure_mode(&self) -> bool {
        self.secure_mode
    }

    /// Transporte de sellado de tiempo (para pruebas o entornos controlados).
    pub fn with_tsa_transport(mut self, t: Arc<dyn TsaTransport>) -> Self {
        self.transport = t;
        self
    }

    pub fn with_enhancer(mut self, e: Arc<dyn SignEnhancer>) -> Self {
        self.enhancer = Some(e);
        self
    }

    /// Firma (o cofirma) un PDF.
    pub fn sign_pdf(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> Result<Vec<u8>, AfirmaError> {
        let algorithm = if algorithm.trim().is_empty() {
            DEFAULT_ALGORITHM
        } else {
            algorithm
        };
        let mut xp = extra.clone();
        check_params(algorithm, &mut xp)?;
        let alg = compose_signature_algorithm(algorithm, key.key_algorithm())?;
        let mut chain = key.certificate_chain();
        if chain.is_empty() {
            chain.push(key.certificate().to_vec());
        }
        if is_true(&xp, INCLUDE_ONLY_SIGNING_CERTIFICATE) {
            chain.truncate(1);
        }
        let sign_time = sign_time_param(&xp);
        let tsa = TsaParams::from_extra_params(&xp)?;
        let ts_type = xp.get(TS_TYPE).unwrap_or("").trim().to_string();
        let mut data = data.to_vec();
        if let Some(tp) = &tsa {
            if ts_type == "2" || ts_type == "3" {
                data = self.document_timestamp(&data, &xp, &sign_time, tp)?;
            }
        }
        let pre = self.presign(&data, alg, &chain, sign_time, &xp)?;
        let pkcs1 = key.sign(&pre.signed_attributes, alg)?;
        match cms::verify_signature(&chain[0], alg.digest, &pre.signed_attributes, &pkcs1) {
            Ok(true) => {}
            Ok(false) => {
                return Err(AfirmaError::new(
                    codes::INVALID_PKCS1_VALUE,
                    "El PKCS#1 de firma obtenido no se genero con el certificado indicado",
                ));
            }
            Err(e) => tracing::warn!("No se ha podido verificar el PKCS#1 generado: {e}"),
        }
        let sig_tsa = tsa.filter(|_| ts_type != "2");
        self.postsign(&pre, &pkcs1, sig_tsa.as_ref(), &xp)
    }

    /// Prefirma: genera la revisión con el hueco y los atributos a firmar
    /// (`PAdESTriPhaseSigner.preSign`).
    pub fn presign(
        &self,
        data: &[u8],
        alg: SignatureAlgorithm,
        chain: &[Vec<u8>],
        sign_time: SignTime,
        xp: &ExtraParams,
    ) -> Result<PadesPreSign, AfirmaError> {
        let prepared = prepare(&PrepareInput {
            pdf: data,
            chain,
            sign_time,
            xp,
            secure_mode: self.secure_mode,
            kind: SigKind::Signature,
        })?;
        let md_alg = match xp.get(PRECALCULATED_HASH_ALGORITHM) {
            Some(v) => afirma_core::algorithms::java_digest_algorithm_name(v)
                .replace('-', "")
                .parse()
                .unwrap_or(alg.digest),
            None => alg.digest,
        };
        let md = prepared.digest(md_alg);
        if chain.is_empty() {
            return Err(AfirmaError::invalid_argument(
                "No se ha indicado el certificado de firma",
            ));
        }
        // Atributos firmados y SignedData de PAdES con afirma-cms (sin
        // signingTime, contentHints ni signerLocation).
        let builder = afirma_cms::SignedDataBuilder::for_pades(&md, alg, chain.to_vec(), xp)?;
        let signed_attributes = builder.signed_attributes()?;
        Ok(PadesPreSign {
            prepared,
            signed_attributes,
            algorithm: alg,
            chain: chain.to_vec(),
            sign_time,
            builder,
        })
    }

    /// Postfirma: compone el CMS con el PKCS#1, añade el sello de firma si se
    /// pide y lo inserta en el PDF.
    pub fn postsign(
        &self,
        pre: &PadesPreSign,
        pkcs1: &[u8],
        tsa: Option<&TsaParams>,
        xp: &ExtraParams,
    ) -> Result<Vec<u8>, AfirmaError> {
        let mut cms = pre.builder.assemble(&pre.signed_attributes, pkcs1)?;
        if let Some(tp) = tsa {
            let ts = Timestamper::with_transport(
                tp.clone(),
                Box::new(SharedTransport(self.transport.clone())),
            );
            match ts.add_timestamp(&cms) {
                Ok(c) => cms = c,
                Err(e) => {
                    tracing::warn!("No se ha podido agregar el sello de tiempo a la firma: {e}")
                }
            }
        }
        if let Some(enh) = &self.enhancer {
            cms = enh.enhance(&cms, xp)?;
        }
        pre.prepared.fill(&cms)
    }

    /// Añade un sello de tiempo de documento (`/DocTimeStamp`).
    pub fn document_timestamp(
        &self,
        data: &[u8],
        xp: &ExtraParams,
        sign_time: &SignTime,
        tp: &TsaParams,
    ) -> Result<Vec<u8>, AfirmaError> {
        let prepared = prepare(&PrepareInput {
            pdf: data,
            chain: &[],
            sign_time: *sign_time,
            xp,
            secure_mode: self.secure_mode,
            kind: SigKind::DocTimeStamp,
        })?;
        let ts = Timestamper::with_transport(
            tp.clone(),
            Box::new(SharedTransport(self.transport.clone())),
        );
        let digest = tp.hash_algorithm;
        let token = ts
            .get_timestamp_token(&prepared.digest(digest), digest)
            .map_err(|e| {
                AfirmaError::new(
                    e.effective_code(),
                    "Error en la composicion del sello de tiempo de la firma",
                )
                .with_cause(e)
            })?;
        let _ = millis(sign_time);
        prepared.fill(&token)
    }
}

/// Fecha de firma (`signTime` o la actual).
pub fn sign_time_param(xp: &ExtraParams) -> SignTime {
    match xp.get(SIGN_TIME) {
        Some(v) => parse_sign_time(v).unwrap_or_else(|| {
            tracing::error!(
                "No se ha podido interpretar la fecha de firma '{v}'; se usara la actual"
            );
            now()
        }),
        None => now(),
    }
}

/// Configuración de los atributos firmados a partir de los parámetros.
pub fn signed_attrs_config(
    alg: SignatureAlgorithm,
    xp: &ExtraParams,
) -> Result<SignedAttrsConfig, AfirmaError> {
    let v2 = if matches!(
        alg.digest,
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512
    ) && matches!(
        alg.key,
        afirma_core::KeyAlgorithm::Rsa | afirma_core::KeyAlgorithm::Ec
    ) {
        true
    } else if let Some(v) = xp.get(SIGNING_CERTIFICATE_V2) {
        v.trim().eq_ignore_ascii_case("true")
    } else {
        alg.digest != DigestAlgorithm::Sha1
    };
    let baseline = xp
        .get(PROFILE)
        .is_some_and(|p| p.eq_ignore_ascii_case("baseline"));
    Ok(SignedAttrsConfig {
        digest: alg.digest,
        signing_certificate_v2: v2,
        include_cert_policies: !is_true(xp, DO_NOT_INCLUDE_POLICY_ON_SIGNING_CERTIFICATE),
        policy: policy_from_params(xp)?,
        commitment_types: commitment_types(xp),
        claimed_roles: xp
            .get(SIGNER_CLAIMED_ROLES)
            .map(|r| r.split('|').map(str::to_string).collect())
            .unwrap_or_default(),
        baseline,
        mime_type: is_true(xp, INCLUDE_MIME_TYPE_ATTRIBUTE).then(|| {
            xp.get(MIME_TYPE)
                .unwrap_or("application/octet-stream")
                .to_string()
        }),
    })
}

/// Política de firma (`AdESPolicy.buildAdESPolicy`).
pub fn policy_from_params(xp: &ExtraParams) -> Result<Option<SigPolicy>, AfirmaError> {
    let Some(id) = xp.get(POLICY_IDENTIFIER) else {
        return Ok(None);
    };
    if id.trim().is_empty() {
        return Err(AfirmaError::invalid_argument(
            "El identificador de politica no puede ser nulo ni vacio",
        ));
    }
    let identifier = {
        let l = id.trim();
        if l.to_ascii_lowercase().starts_with("urn:oid:") {
            l[8..].to_string()
        } else {
            l.to_string()
        }
    };
    let hash = xp.get(POLICY_IDENTIFIER_HASH).filter(|h| !h.is_empty());
    let (hash_bytes, alg_oid) = match hash {
        Some(h) if h != "0" => {
            let alg = xp.get(POLICY_IDENTIFIER_HASH_ALGORITHM).filter(|a| !a.is_empty()).ok_or_else(|| {
                AfirmaError::invalid_argument("Si se indica la huella digital del identificador de politica es obligatorio indicar tambien el algoritmo")
            })?;
            let bytes = afirma_core::base64_decode_lenient(h).map_err(|_| {
                AfirmaError::invalid_argument(
                    "La huella digital de la politica debe estar en formato Base64",
                )
            })?;
            let d: DigestAlgorithm = afirma_core::algorithms::java_digest_algorithm_name(alg)
                .replace('-', "")
                .parse()
                .map_err(|_| {
                    AfirmaError::invalid_argument(format!(
                        "Algoritmo de huella de politica no soportado: {alg}"
                    ))
                })?;
            (bytes, d.oid().to_string())
        }
        _ => {
            let d: DigestAlgorithm = xp
                .get(POLICY_IDENTIFIER_HASH_ALGORITHM)
                .and_then(|a| {
                    afirma_core::algorithms::java_digest_algorithm_name(a)
                        .replace('-', "")
                        .parse()
                        .ok()
                })
                .unwrap_or(DigestAlgorithm::Sha512);
            let content = download_policy(&identifier).map_err(|e| {
                AfirmaError::invalid_argument(format!(
                    "Si no se especifica la huella digital de la politica es necesario que el identificador sea una URL accesible universalmente: {e}"
                ))
            })?;
            (d.digest(&content), d.oid().to_string())
        }
    };
    let qualifier = match xp.get(POLICY_QUALIFIER).filter(|q| !q.is_empty()) {
        Some(q) => {
            if !q.contains("://") {
                return Err(AfirmaError::invalid_argument(
                    "El calificador de la politica debe ser una URL valida",
                ));
            }
            Some(q.to_string())
        }
        None => None,
    };
    Ok(Some(SigPolicy {
        identifier,
        hash: hash_bytes,
        hash_algorithm_oid: alg_oid,
        qualifier,
    }))
}

/// La configuración local de atributos no descarga políticas: la firma usa
/// `afirma-cms`, que sí lo hace (`AdESPolicy`).
fn download_policy(url: &str) -> Result<Vec<u8>, String> {
    Err(format!("no se puede descargar {url}"))
}

/// `CommitmentTypeIndicationsHelper.getCommitmentTypeIndications`.
pub fn commitment_types(xp: &ExtraParams) -> Vec<CommitmentType> {
    let mut out = Vec::new();
    let Some(n) = xp.get(COMMITMENT_TYPE_INDICATIONS) else {
        return out;
    };
    let n = match parse_java_int(n) {
        Some(n) if n >= 1 => n,
        _ => return out,
    };
    for i in 0..=n {
        let Some(id) = xp.get(&format!("commitmentTypeIndication{i}Identifier")) else {
            continue;
        };
        let oid = match id {
            "1" => "1.2.840.113549.1.9.16.6.1",
            "2" => "1.2.840.113549.1.9.16.6.2",
            "3" => "1.2.840.113549.1.9.16.6.3",
            "4" => "1.2.840.113549.1.9.16.6.4",
            "5" => "1.2.840.113549.1.9.16.6.5",
            "6" => "1.2.840.113549.1.9.16.6.6",
            _ => continue,
        };
        let qualifiers = xp
            .get(&format!(
                "commitmentTypeIndication{i}CommitmentTypeQualifiers"
            ))
            .map(|q| q.split('|').map(str::to_string).collect());
        out.push(CommitmentType {
            oid: oid.into(),
            qualifiers,
        });
    }
    out
}

/// `isPdfFile`.
pub fn is_pdf_file(data: &[u8]) -> bool {
    if data.len() < PDF_MIN_FILE_SIZE || !has_pdf_header(data) {
        return false;
    }
    match PdfDoc::open(data, None) {
        Ok(_) => true,
        Err(crate::pdf::doc::OpenError::NeedsPassword)
        | Err(crate::pdf::doc::OpenError::BadPassword) => true,
        Err(_) => false,
    }
}

/// Árbol de firmantes (`getSignersStructure`): firmas de la más reciente a
/// la más antigua, sin los sellos de documento.
pub fn signers_structure(data: &[u8], xp: &ExtraParams) -> SignersTree {
    let mut tree = SignersTree::default();
    if !is_pdf_file(data) {
        return tree;
    }
    let password = xp.get(OWNER_PASSWORD).or_else(|| xp.get(USER_PASSWORD));
    let Ok(doc) = PdfDoc::open(data, password) else {
        return tree;
    };
    let (sigs, _) = doc.signatures();
    for s in sigs {
        if s.sub_filter().as_deref() == Some(b"ETSI.RFC3161".as_slice()) {
            continue;
        }
        let Ok(data) = crate::validate::SignatureData::read(&doc, &s) else {
            tracing::warn!("Firma corrupta en el campo {}", s.name);
            continue;
        };
        let si = data.cms.as_ref().and_then(|sd| sd.signer_infos.first());
        let signing_time = s
            .dict
            .get(b"M")
            .ok()
            .and_then(|m| m.as_str().ok())
            .and_then(|m| parse_pdf_date(&String::from_utf8_lossy(m)))
            .map(|t| t.with_timezone(&chrono::Utc))
            .or_else(|| {
                si.and_then(|si| si.signed_attr(cms::OID_SIGNING_TIME))
                    .and_then(|a| a.values.first())
                    .and_then(|v| afirma_cms::asn1::Tlv::parse_single(v).ok()?.as_time().ok())
            });
        let timestamping_time = si
            .and_then(|si| si.unsigned_attr(cms::OID_SIGNATURE_TIMESTAMP))
            .and_then(|a| a.values.first())
            .and_then(|t| cms::timestamp_gen_time(t))
            .into_iter()
            .collect();
        tree.signers.push(SignerNode {
            info: SimpleSignInfo {
                certs: data.chain,
                signing_time,
                sign_algorithm: Some(data.algorithm_name),
                pkcs1: data.pkcs1,
                sign_format: None,
                timestamping_time,
            },
            countersigners: Vec::new(),
        });
    }
    tree
}

/// `getSignedName(originalName)` estático: `x.pdf` → `x.signed.pdf`
/// (sustituyendo todas las apariciones de `.pdf`, como Java).
pub fn signed_file_name(original: Option<&str>) -> String {
    match original {
        None => "signed.pdf".into(),
        Some(n) if n.ends_with(".pdf") => n.replace(".pdf", ".signed.pdf"),
        Some(n) if n.ends_with(".PDF") => n.replace(".PDF", ".signed.pdf"),
        Some(n) => format!("{n}.signed.pdf"),
    }
}

impl Signer for PadesSigner {
    fn format_name(&self) -> &'static str {
        self.format
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        self.sign_pdf(data, algorithm, key, extra)
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        self.sign_pdf(sign, algorithm, key, extra)
    }

    fn countersign(
        &self,
        _sign: &[u8],
        _algorithm: &str,
        _target: &CounterSignTarget,
        _key: &dyn SigningKey,
        _extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        Err(AfirmaError::unsupported(
            "No es posible realizar contrafirmas de ficheros PDF",
        ))
    }

    fn signers_structure(
        &self,
        sign: &[u8],
        params: &ExtraParams,
    ) -> afirma_core::Result<SignersTree> {
        Ok(signers_structure(sign, params))
    }

    fn is_sign(&self, data: &[u8], params: &ExtraParams) -> bool {
        if !is_pdf_file(data) {
            return false;
        }
        if !signers_structure(data, params).is_empty() {
            return true;
        }
        // Java consulta aquí las propiedades del sistema en lugar de los
        // parámetros; se usan los parámetros (ver desviaciones).
        if is_true(params, ALLOW_COSIGNING_UNREGISTERED_SIGNATURES) {
            let password = params
                .get(OWNER_PASSWORD)
                .or_else(|| params.get(USER_PASSWORD));
            if let Ok(doc) = PdfDoc::open(data, password) {
                return prepare::has_unregistered_signatures(&doc);
            }
        }
        false
    }

    fn is_valid_data_file(&self, data: &[u8]) -> bool {
        is_pdf_file(data)
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        let in_text = in_text.unwrap_or("");
        match original {
            None => "signed.pdf".into(),
            Some(n) if n.to_lowercase().ends_with(".pdf") => {
                format!("{}{in_text}.pdf", &n[..n.len() - 4])
            }
            Some(n) => format!("{n}{in_text}.pdf"),
        }
    }

    fn get_data(&self, sign: &[u8], params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        if !self.is_sign(sign, params) {
            return Err(AfirmaError::invalid_signature_format(
                "El documento introducido no contiene una firma valida",
            ));
        }
        Ok(Some(sign.to_vec()))
    }

    fn sign_info(&self, sign: &[u8], params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        if sign.is_empty() {
            return Err(AfirmaError::invalid_argument(
                "No se han introducido datos para analizar",
            ));
        }
        if !self.is_sign(sign, params) {
            return Err(AfirmaError::invalid_signature_format(
                "El documento introducido no contiene una firma valida",
            ));
        }
        Ok(SignInfo {
            format: FORMAT_PDF.into(),
            ..SignInfo::default()
        })
    }
}

/// Primera firma cuyo subfiltro está registrado (para el formato `AUTO`,
/// `configureRespectfulProperties`). No copia `ETSI.RFC3161` (corrige el
/// fallo de Java).
pub fn configure_respectful_properties(data: &[u8], config: &mut ExtraParams) {
    if config.contains(SIGNATURE_SUBFILTER) {
        return;
    }
    let Ok(doc) = PdfDoc::open(
        data,
        config
            .get(OWNER_PASSWORD)
            .or_else(|| config.get(USER_PASSWORD)),
    ) else {
        return;
    };
    for (_, o) in doc.all_objects() {
        let lopdf::Object::Dictionary(d) = o else {
            continue;
        };
        if d.get(b"Type").and_then(lopdf::Object::as_name).ok() != Some(b"Sig".as_slice()) {
            continue;
        }
        if let Ok(sf) = d.get(b"SubFilter").and_then(lopdf::Object::as_name) {
            if matches!(
                sf,
                b"adbe.pkcs7.detached" | b"ETSI.CAdES.detached" | b"adbe.pkcs7.sha1"
            ) {
                config.set(
                    SIGNATURE_SUBFILTER,
                    String::from_utf8_lossy(sf).into_owned(),
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_names() {
        assert_eq!(signed_file_name(None), "signed.pdf");
        assert_eq!(signed_file_name(Some("x.pdf")), "x.signed.pdf");
        assert_eq!(
            signed_file_name(Some("a.pdf.pdf")),
            "a.signed.pdf.signed.pdf"
        );
        assert_eq!(signed_file_name(Some("X.PDF")), "X.signed.pdf");
        assert_eq!(signed_file_name(Some("doc")), "doc.signed.pdf");
        let s = PadesSigner::new();
        assert_eq!(
            s.signed_name(Some("x.PDF"), Some("_firmado")),
            "x_firmado.pdf"
        );
        assert_eq!(s.signed_name(Some("x.txt"), None), "x.txt.pdf");
        assert_eq!(s.signed_name(None, None), "signed.pdf");
    }

    #[test]
    fn commitment_parsing() {
        let xp: ExtraParams = [
            ("commitmentTypeIndications", "1"),
            ("commitmentTypeIndication0Identifier", "1"),
            ("commitmentTypeIndication1Identifier", "5"),
            (
                "commitmentTypeIndication1CommitmentTypeQualifiers",
                "1.2.3|1.2.4",
            ),
            ("commitmentTypeIndication2Identifier", "6"),
        ]
        .into_iter()
        .collect();
        let c = commitment_types(&xp);
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].oid, "1.2.840.113549.1.9.16.6.5");
        assert_eq!(c[1].qualifiers.as_ref().unwrap().len(), 2);
    }
}
