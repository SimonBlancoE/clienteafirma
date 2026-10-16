//! Firmas CMS/PKCS#7 (`AOCMSSigner`, `GenSignedData`, `CoSigner`,
//! `CounterSigner`).

use afirma_core::algorithms::{SignatureAlgorithm, compose_signature_algorithm};
use afirma_core::error::{AfirmaError, codes};
use afirma_core::{CounterSignTarget, ExtraParams, SignInfo, Signer, SignersTree, SigningKey};
use chrono::{DateTime, Utc};

use crate::alg;
use crate::asn1::{der, tags};
use crate::cades::{now, signed_name_with};
use crate::cert::CertView;
use crate::cms::{
    self, SignedData, SignedDataParts, SignerInfo, encode_attribute, encode_signer_info, to_der_preserving,
};
use crate::{detect, oids, tree};

/// Nombre del formato.
pub const FORMAT_CMS: &str = "CMS/PKCS#7";
/// Algoritmo por defecto de `AOCMSSigner` (`AOSignConstants.DEFAULT_SIGN_ALGO`).
pub const DEFAULT_SIGN_ALGO: &str = "SHA512withRSA";

/// Firmador CMS/PKCS#7.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmsSigner;

fn chain_of(key: &dyn SigningKey) -> afirma_core::Result<Vec<Vec<u8>>> {
    let chain = key.certificate_chain();
    if chain.is_empty() {
        return Err(AfirmaError::invalid_argument("La cadena de certificados debe contener al menos un elemento"));
    }
    Ok(chain)
}

fn resolve(algorithm: &str, key: &dyn SigningKey) -> afirma_core::Result<SignatureAlgorithm> {
    let algorithm = if algorithm.is_empty() { DEFAULT_SIGN_ALGO } else { algorithm };
    compose_signature_algorithm(algorithm, key.key_algorithm())
}

fn content_type_attr() -> Vec<u8> {
    encode_attribute(oids::CONTENT_TYPE, &[der::oid_str(oids::DATA)])
}

fn signing_time_attr(now: &DateTime<Utc>) -> Vec<u8> {
    encode_attribute(oids::SIGNING_TIME, &[der::utc_time(now)])
}

fn message_digest_attr(md: &[u8]) -> Vec<u8> {
    encode_attribute(oids::MESSAGE_DIGEST, &[der::octet_string(md)])
}

fn serial_number_attr(cert: &CertView<'_>) -> Vec<u8> {
    encode_attribute(oids::SERIAL_NUMBER, &[der::printable_string(&cert.serial_decimal())])
}

/// Firma y compone un SignerInfo CMS a partir de sus atributos firmados.
fn signer_info(
    key: &dyn SigningKey,
    cert: &CertView<'_>,
    alg: SignatureAlgorithm,
    attrs: &[Vec<u8>],
) -> afirma_core::Result<Vec<u8>> {
    let set = der::set_of(attrs);
    // CMS firma directamente con la clave (sin la autoverificación de AOPkcs1Signer).
    let sig = key.sign(&set, alg).map_err(AfirmaError::from)?;
    Ok(encode_signer_info(
        &cert.issuer_and_serial(),
        &alg::digest_alg_id(alg.digest),
        Some(&set),
        &alg::alg_id_null(alg::sign_signature_alg_oid(alg)),
        &sig,
        None,
    ))
}

fn view(der: &[u8]) -> afirma_core::Result<CertView<'_>> {
    CertView::parse(der).map_err(|e| {
        AfirmaError::new(codes::ENCODING_SIGNING_CERTIFICATE, format!("Error en el certificado de firma: {e}"))
    })
}

/// Firma CMS (`AOCMSSigner.sign`).
pub fn sign_at(
    data: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
    now: DateTime<Utc>,
) -> afirma_core::Result<Vec<u8>> {
    let chain = chain_of(key)?;
    let alg = resolve(algorithm, key)?;
    let precalculated = extra.contains("precalculatedHashAlgorithm");
    let omit = extra.get_or("mode", "explicit") == "explicit" || precalculated;
    let apply_date = extra.get_or("applySystemDate", "true").eq_ignore_ascii_case("true");
    let md = if precalculated && !data.is_empty() { data.to_vec() } else { alg.digest.digest(data) };
    let cert0 = view(&chain[0])?;
    let mut attrs = vec![content_type_attr()];
    if apply_date {
        attrs.push(signing_time_attr(&now));
    }
    attrs.push(message_digest_attr(&md));
    let si = signer_info(key, &cert0, alg, &attrs)?;
    Ok(SignedDataParts {
        digest_algorithms: vec![alg::digest_alg_id(alg.digest)],
        encap_content_info: cms::encap_content_info(if omit { None } else { Some(data) }),
        certificates: Some(chain),
        crls: None,
        signer_infos: vec![si],
    }
    .encode())
}

fn parse_cms(sign: &[u8]) -> afirma_core::Result<SignedData<'_>> {
    if !detect::is_cms_signed_data(sign) {
        return Err(AfirmaError::invalid_signature_format("Los datos no se corresponden con una firma CMS valida"));
    }
    SignedData::parse(sign).map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))
}

/// Cofirma CMS con datos (`CoSigner.coSigner(parameters, sign, ...)`): el
/// `encapContentInfo` se reconstruye según `mode`.
pub fn cosign_with_data_at(
    data: &[u8],
    sign: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
    now: DateTime<Utc>,
) -> afirma_core::Result<Vec<u8>> {
    let chain = chain_of(key)?;
    let alg = resolve(algorithm, key)?;
    let precalculated = extra.contains("precalculatedHashAlgorithm");
    let omit = extra.get_or("mode", "explicit") == "explicit" || precalculated;
    let sd = parse_cms(sign)?;
    let cert0 = view(&chain[0])?;
    let mut certificates = sd.certificates.as_ref().map(cms::set_elements_der).unwrap_or_default();
    certificates.extend(chain.iter().cloned());
    let attrs = if precalculated {
        vec![content_type_attr(), signing_time_attr(&now), message_digest_attr(data), serial_number_attr(&cert0)]
    } else {
        vec![content_type_attr(), signing_time_attr(&now), message_digest_attr(&alg.digest.digest(data))]
    };
    let mut signer_infos: Vec<Vec<u8>> = sd.signer_infos.iter().map(|si| to_der_preserving(&si.raw)).collect();
    signer_infos.push(signer_info(key, &cert0, alg, &attrs)?);
    Ok(SignedDataParts {
        digest_algorithms: cms::digest_algorithms_with(&sd.digest_algorithms, &alg::digest_alg_id(alg.digest)),
        encap_content_info: cms::encap_content_info(if omit { None } else { Some(data) }),
        certificates: Some(certificates),
        crls: None,
        signer_infos,
    }
    .encode())
}

/// Cofirma CMS sin datos (`CoSigner.coSigner(algorithm, chain, sign, ...)`).
pub fn cosign_at(
    sign: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    now: DateTime<Utc>,
) -> afirma_core::Result<Vec<u8>> {
    let chain = chain_of(key)?;
    let alg = resolve(algorithm, key)?;
    let sd = parse_cms(sign)?;
    let cert0 = view(&chain[0])?;
    let content = sd.content();
    let mut certificates = sd.certificates.as_ref().map(cms::set_elements_der).unwrap_or_default();
    certificates.extend(chain.iter().cloned());
    // Huella del ÚLTIMO firmante con el mismo algoritmo (el bucle de Java no se detiene).
    let mut md = None;
    for si in &sd.signer_infos {
        if si.digest_oid.is(alg.digest.oid()) {
            if let Some(m) = si.message_digest() {
                md = Some(m);
            }
        }
    }
    let attrs = match (&content, &md) {
        (Some(c), _) => vec![content_type_attr(), signing_time_attr(&now), message_digest_attr(&alg.digest.digest(c))],
        (None, Some(m)) => {
            vec![content_type_attr(), signing_time_attr(&now), message_digest_attr(m), serial_number_attr(&cert0)]
        }
        (None, None) => {
            return Err(AfirmaError::new(
                codes::SIGNATURE_DOESNT_CONTAIN_DATA,
                "No se puede crear la cofirma ya que no se han encontrado ni los datos firmados ni una huella digital compatible con el algoritmo de firma",
            ));
        }
    };
    let mut signer_infos: Vec<Vec<u8>> = sd.signer_infos.iter().map(|si| to_der_preserving(&si.raw)).collect();
    signer_infos.push(signer_info(key, &cert0, alg, &attrs)?);
    Ok(SignedDataParts {
        digest_algorithms: cms::digest_algorithms_with(&sd.digest_algorithms, &alg::digest_alg_id(alg.digest)),
        encap_content_info: to_der_preserving(&sd.encap_content_info),
        certificates: Some(certificates),
        crls: None,
        signer_infos,
    }
    .encode())
}

/// Elemento de los atributos no firmados reconstruidos por `CounterSigner`.
enum Item {
    /// Atributo de sello de tiempo conservado.
    Attr(Vec<u8>),
    /// SignerInfo (contrafirma) que va en su propio atributo `counterSignature`.
    Signer(Vec<u8>),
}

fn counter_attr(signer_infos: &[Vec<u8>]) -> Vec<u8> {
    encode_attribute(oids::COUNTER_SIGNATURE, signer_infos)
}

fn items_to_attrs(items: Vec<Item>) -> Vec<Vec<u8>> {
    items
        .into_iter()
        .map(|i| match i {
            Item::Attr(a) => a,
            Item::Signer(s) => counter_attr(&[s]),
        })
        .collect()
}

struct CounterCtx<'k> {
    key: &'k dyn SigningKey,
    cert: Vec<u8>,
    alg: SignatureAlgorithm,
    now: DateTime<Utc>,
    actual: usize,
}

fn walk_err(e: impl std::fmt::Display) -> AfirmaError {
    AfirmaError::new(codes::UNKWNON_BINARY_SIGNING_ERROR, format!("Error generando la Contrafirma PKCS#7: {e}"))
}

impl CounterCtx<'_> {
    /// `generateCounterSignSignedInfo`.
    fn new_countersignature(&self, target: &SignerInfo<'_>) -> afirma_core::Result<Vec<u8>> {
        let cert = view(&self.cert)?;
        let attrs = vec![
            signing_time_attr(&self.now),
            message_digest_attr(&self.alg.digest.digest(&target.signature_value())),
            serial_number_attr(&cert),
        ];
        signer_info(self.key, &cert, self.alg, &attrs)
    }

    /// Recorre los atributos no firmados: los sellos se conservan, cada valor
    /// SEQUENCE de cualquier otro atributo se trata como SignerInfo y los
    /// demás valores se descartan.
    fn collect<F>(&mut self, si: &SignerInfo<'_>, mut on_child: F) -> afirma_core::Result<Vec<Item>>
    where
        F: FnMut(&mut Self, &SignerInfo<'_>) -> afirma_core::Result<Vec<u8>>,
    {
        let mut items = Vec::new();
        for attr in si.unsigned_attributes().map_err(walk_err)? {
            if attr.is(oids::SIGNATURE_TIMESTAMP_TOKEN) {
                items.push(Item::Attr(to_der_preserving(&attr.raw)));
                continue;
            }
            for v in &attr.values {
                if v.tag == tags::SEQUENCE {
                    let child = SignerInfo::parse(*v).map_err(walk_err)?;
                    let out = on_child(self, &child)?;
                    items.push(Item::Signer(out));
                }
            }
        }
        Ok(items)
    }

    /// `getCounterUnsignedAtributes` (TREE).
    fn tree(&mut self, si: &SignerInfo<'_>) -> afirma_core::Result<Vec<u8>> {
        if si.unsigned_attrs.is_none() {
            let attrs = vec![counter_attr(&[self.new_countersignature(si)?])];
            return Ok(cms::rebuild_signer_info(si, Some(&attrs)));
        }
        let mut items = self.collect(si, |ctx, c| ctx.tree(c))?;
        items.push(Item::Signer(self.new_countersignature(si)?));
        Ok(cms::rebuild_signer_info(si, Some(&items_to_attrs(items))))
    }

    /// `getCounterLeafUnsignedAtributes` (LEAFS).
    fn leafs(&mut self, si: &SignerInfo<'_>) -> afirma_core::Result<Vec<u8>> {
        if si.unsigned_attrs.is_none() {
            let attrs = vec![counter_attr(&[self.new_countersignature(si)?])];
            return Ok(cms::rebuild_signer_info(si, Some(&attrs)));
        }
        let mut items = self.collect(si, |ctx, c| ctx.leafs(c))?;
        let attrs = match items.len() {
            0 => vec![counter_attr(&[])],
            1 => match items.pop() {
                Some(Item::Attr(a)) => vec![a, counter_attr(&[self.new_countersignature(si)?])],
                Some(Item::Signer(s)) => vec![counter_attr(&[s])],
                None => Vec::new(),
            },
            _ => items_to_attrs(items),
        };
        Ok(cms::rebuild_signer_info(si, Some(&attrs)))
    }

    /// `getCounterNodeUnsignedAtributes(si, ...)`: contrafirma el nodo
    /// objetivo conservando tal cual sus contrafirmas.
    fn node_target(&mut self, si: &SignerInfo<'_>) -> afirma_core::Result<Vec<u8>> {
        if si.unsigned_attrs.is_none() {
            let attrs = vec![counter_attr(&[self.new_countersignature(si)?])];
            return Ok(cms::rebuild_signer_info(si, Some(&attrs)));
        }
        let mut items = self.collect(si, |_, c| Ok(to_der_preserving(&c.raw)))?;
        items.push(Item::Signer(self.new_countersignature(si)?));
        Ok(cms::rebuild_signer_info(si, Some(&items_to_attrs(items))))
    }

    /// `getCounterNodeUnsignedAtributes(si, ..., node)`: busca el nodo
    /// objetivo numerando en preorden.
    fn node_walk(&mut self, si: &SignerInfo<'_>, target: usize) -> afirma_core::Result<Vec<u8>> {
        if si.unsigned_attrs.is_none() {
            return Ok(cms::rebuild_signer_info(si, None));
        }
        let items = self.collect(si, |ctx, c| {
            ctx.actual += 1;
            if ctx.actual == target {
                ctx.node_target(c)
            } else if ctx.actual < target {
                ctx.node_walk(c, target)
            } else {
                Ok(to_der_preserving(&c.raw))
            }
        })?;
        if items.is_empty() {
            return Err(walk_err("nodo sin atributos no firmados reconocibles"));
        }
        Ok(cms::rebuild_signer_info(si, Some(&items_to_attrs(items))))
    }

    /// `counterNode`.
    fn node(&mut self, sd: &SignedData<'_>, target: usize) -> afirma_core::Result<Vec<Vec<u8>>> {
        self.actual = 0;
        let mut out = Vec::new();
        for si in &sd.signer_infos {
            let r = if self.actual == target { self.node_target(si)? } else { self.node_walk(si, target)? };
            self.actual += 1;
            out.push(r);
        }
        Ok(out)
    }
}

/// `ReadNodesTree.simplyArray`: elimina duplicados conservando el orden.
pub fn simply_array(nodes: &[usize]) -> Vec<usize> {
    let mut out = Vec::new();
    for n in nodes {
        if !out.contains(n) {
            out.push(*n);
        }
    }
    out
}

/// `ReadNodesTree.readNodesFromSigners`: índices (preorden) de los nodos
/// cuyo CN coincide con alguno de los indicados, ordenados.
pub fn nodes_from_signers(signers: &[String], sign: &[u8]) -> afirma_core::Result<Vec<usize>> {
    let names = tree::signer_names_preorder(sign)?;
    let mut out = Vec::new();
    for (i, name) in names.iter().enumerate() {
        for s in signers {
            if name == s {
                out.push(i);
            }
        }
    }
    let mut out = simply_array(&out);
    out.sort_unstable();
    Ok(out)
}

/// Contrafirma CMS (`AOCMSSigner.countersign`).
pub fn countersign_at(
    sign: &[u8],
    algorithm: &str,
    target: &CounterSignTarget,
    key: &dyn SigningKey,
    now: DateTime<Utc>,
) -> afirma_core::Result<Vec<u8>> {
    let chain = chain_of(key)?;
    let alg = resolve(algorithm, key)?;
    let sd = parse_cms(sign)?;
    let mut certificates = sd.certificates.as_ref().map(cms::set_elements_der).unwrap_or_default();
    certificates.push(chain[0].clone());
    let mut ctx = CounterCtx { key, cert: chain[0].clone(), alg, now, actual: 0 };
    let parts = |signer_infos: Vec<Vec<u8>>| SignedDataParts {
        digest_algorithms: cms::set_elements_der(&sd.digest_algorithms),
        encap_content_info: to_der_preserving(&sd.encap_content_info),
        certificates: Some(certificates.clone()),
        crls: None,
        signer_infos,
    };
    match target {
        CounterSignTarget::Tree => {
            let sis = sd.signer_infos.iter().map(|si| ctx.tree(si)).collect::<afirma_core::Result<Vec<_>>>()?;
            Ok(parts(sis).encode())
        }
        CounterSignTarget::Leafs => {
            let sis = sd.signer_infos.iter().map(|si| ctx.leafs(si)).collect::<afirma_core::Result<Vec<_>>>()?;
            Ok(parts(sis).encode())
        }
        CounterSignTarget::Nodes(_) | CounterSignTarget::Signers(_) => {
            let targets = match target {
                CounterSignTarget::Nodes(n) => simply_array(n),
                CounterSignTarget::Signers(s) => nodes_from_signers(s, sign)?,
                _ => Vec::new(),
            };
            if targets.is_empty() {
                return Ok(to_der_preserving(&sd.content_info));
            }
            // Se procesan desde el último objetivo y se relee la firma tras cada uno.
            let mut current: Vec<u8> = sign.to_vec();
            for &t in targets.iter().rev() {
                let cur_sd = SignedData::parse(&current).map_err(walk_err)?;
                let sis = ctx.node(&cur_sd, t)?;
                current = parts(sis).encode();
            }
            Ok(current)
        }
    }
}

impl Signer for CmsSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_CMS
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
        match data {
            Some(d) => cosign_with_data_at(d, sign, algorithm, key, extra, now()),
            None => cosign_at(sign, algorithm, key, now()),
        }
    }

    fn countersign(
        &self,
        sign: &[u8],
        algorithm: &str,
        target: &CounterSignTarget,
        key: &dyn SigningKey,
        _extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        countersign_at(sign, algorithm, target, key, now())
    }

    fn signers_structure(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignersTree> {
        tree::read_signers_tree(sign)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        detect::is_cms_signed_data(data)
    }

    fn is_valid_data_file(&self, _data: &[u8]) -> bool {
        true
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        signed_name_with(original, in_text, ".csig")
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        if !detect::is_cms_signed_data(sign) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un objeto de firma",
            ));
        }
        detect::obtain_data(sign)
    }

    fn sign_info(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        if !detect::is_cms_signed_data(sign) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un objeto de firma",
            ));
        }
        Ok(SignInfo { format: FORMAT_CMS.to_string(), ..Default::default() })
    }
}
