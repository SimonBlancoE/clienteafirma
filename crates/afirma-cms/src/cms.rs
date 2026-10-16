//! Modelo de lectura y escritura de estructuras CMS (RFC 5652):
//! `ContentInfo`, `SignedData`, `SignerInfo` y atributos.
//!
//! La lectura conserva los bytes originales de cada elemento (vistas sobre el
//! búfer de entrada) para poder copiar firmas existentes sin alterarlas. La
//! escritura produce DER con los SET ordenados como hace Bouncy Castle.

use chrono::{DateTime, Utc};

use crate::asn1::{Asn1Error, Class, Oid, Result, Tag, Tlv, der, tags};
use crate::cert::CertView;
use crate::oids;

/// `[0]` construido (contexto).
pub const CTX0: Tag = Tag::context(0, true);
/// `[1]` construido (contexto).
pub const CTX1: Tag = Tag::context(1, true);

fn invalid(msg: impl Into<String>) -> Asn1Error {
    Asn1Error::Invalid(msg.into())
}

/// Atributo CMS (`Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }`).
#[derive(Debug, Clone)]
pub struct Attribute<'a> {
    pub raw: Tlv<'a>,
    pub oid: Oid,
    pub values: Vec<Tlv<'a>>,
}

impl<'a> Attribute<'a> {
    pub fn parse(tlv: Tlv<'a>) -> Result<Self> {
        let tlv = tlv.expect(tags::SEQUENCE)?;
        let parts = tlv.children()?;
        let oid = parts.first().ok_or(Asn1Error::Truncated)?.as_oid()?;
        let set = parts.get(1).ok_or(Asn1Error::Truncated)?;
        if !set.tag.same_number(tags::SET) || set.tag.class != Class::Universal {
            return Err(invalid("los valores del atributo no son un SET"));
        }
        Ok(Attribute { raw: tlv, oid, values: set.children()? })
    }

    pub fn is(&self, dotted: &str) -> bool {
        self.oid.is(dotted)
    }

    /// Primer valor.
    pub fn first_value(&self) -> Option<Tlv<'a>> {
        self.values.first().copied()
    }
}

/// Codifica un atributo con sus valores (ya codificados) en un SET DER.
pub fn encode_attribute(oid: &str, values: &[Vec<u8>]) -> Vec<u8> {
    der::sequence([der::oid_str(oid), der::set_of(values)])
}

/// Lee los atributos de un SET (o de su versión con etiqueta implícita).
pub fn parse_attributes<'a>(set: &Tlv<'a>) -> Result<Vec<Attribute<'a>>> {
    set.children()?.into_iter().map(Attribute::parse).collect()
}

/// `SignerInfo` leído conservando su codificación.
#[derive(Debug, Clone)]
pub struct SignerInfo<'a> {
    pub raw: Tlv<'a>,
    pub version: i64,
    /// `SignerIdentifier`: `IssuerAndSerialNumber` o `[0] SubjectKeyIdentifier`.
    pub sid: Tlv<'a>,
    pub digest_algorithm: Tlv<'a>,
    pub digest_oid: Oid,
    /// `[0] IMPLICIT SignedAttributes` tal y como aparece.
    pub signed_attrs: Option<Tlv<'a>>,
    pub signature_algorithm: Tlv<'a>,
    pub signature_oid: Oid,
    /// `OCTET STRING` con el valor de firma.
    pub signature: Tlv<'a>,
    /// `[1] IMPLICIT UnsignedAttributes` tal y como aparece.
    pub unsigned_attrs: Option<Tlv<'a>>,
}

fn alg_oid(t: &Tlv<'_>) -> Result<Oid> {
    t.expect(tags::SEQUENCE)?.children()?.first().ok_or(Asn1Error::Truncated)?.as_oid()
}

impl<'a> SignerInfo<'a> {
    pub fn parse(tlv: Tlv<'a>) -> Result<Self> {
        let tlv = tlv.expect(tags::SEQUENCE)?;
        let mut it = tlv.children()?.into_iter().peekable();
        let version = it.next().ok_or(Asn1Error::Truncated)?.as_i64()?;
        let sid = it.next().ok_or(Asn1Error::Truncated)?;
        let digest_algorithm = it.next().ok_or(Asn1Error::Truncated)?;
        let digest_oid = alg_oid(&digest_algorithm)?;
        let signed_attrs = if it.peek().is_some_and(|t| t.tag.class == Class::Context && t.tag.number == 0) {
            it.next()
        } else {
            None
        };
        let signature_algorithm = it.next().ok_or(Asn1Error::Truncated)?;
        let signature_oid = alg_oid(&signature_algorithm)?;
        let signature = it.next().ok_or(Asn1Error::Truncated)?;
        if !signature.tag.same_number(tags::OCTET_STRING) || signature.tag.class != Class::Universal {
            return Err(invalid("el valor de firma no es un OCTET STRING"));
        }
        let unsigned_attrs = if it.peek().is_some_and(|t| t.tag.class == Class::Context && t.tag.number == 1) {
            it.next()
        } else {
            None
        };
        Ok(SignerInfo {
            raw: tlv,
            version,
            sid,
            digest_algorithm,
            digest_oid,
            signed_attrs,
            signature_algorithm,
            signature_oid,
            signature,
            unsigned_attrs,
        })
    }

    /// Valor de la firma (PKCS#1 o ECDSA DER).
    pub fn signature_value(&self) -> Vec<u8> {
        self.signature.flatten_content().unwrap_or_default()
    }

    /// Atributos firmados.
    pub fn signed_attributes(&self) -> Result<Vec<Attribute<'a>>> {
        match &self.signed_attrs {
            Some(s) => parse_attributes(s),
            None => Ok(Vec::new()),
        }
    }

    /// Atributos no firmados.
    pub fn unsigned_attributes(&self) -> Result<Vec<Attribute<'a>>> {
        match &self.unsigned_attrs {
            Some(s) => parse_attributes(s),
            None => Ok(Vec::new()),
        }
    }

    /// Primer atributo firmado con el OID dado.
    pub fn signed_attr(&self, oid: &str) -> Option<Attribute<'a>> {
        self.signed_attributes().ok()?.into_iter().find(|a| a.is(oid))
    }

    /// Primer atributo no firmado con el OID dado.
    pub fn unsigned_attr(&self, oid: &str) -> Option<Attribute<'a>> {
        self.unsigned_attributes().ok()?.into_iter().find(|a| a.is(oid))
    }

    pub fn has_signed_attr(&self, oid: &str) -> bool {
        self.signed_attr(oid).is_some()
    }

    pub fn has_unsigned_attr(&self, oid: &str) -> bool {
        self.unsigned_attr(oid).is_some()
    }

    /// Codificación DER de los atributos firmados como `SET OF` (etiqueta
    /// 0x31): los datos que se firman. Se conservan el orden y el contenido
    /// originales (solo se pasa a longitudes definidas si hiciera falta).
    pub fn signed_attrs_to_be_signed(&self) -> Option<Vec<u8>> {
        let s = self.signed_attrs.as_ref()?;
        let definite = s.to_definite();
        let t = Tlv::parse_single(&definite).ok()?;
        Some(der::tlv(tags::SET, t.value))
    }

    /// Valor del atributo `messageDigest`.
    pub fn message_digest(&self) -> Option<Vec<u8>> {
        self.signed_attr(oids::MESSAGE_DIGEST)?.first_value()?.octet_string_content().ok()
    }

    /// Valor del atributo `signingTime` (UTCTime o GeneralizedTime).
    pub fn signing_time(&self) -> Option<DateTime<Utc>> {
        self.signed_attr(oids::SIGNING_TIME)?.first_value()?.as_time().ok()
    }

    /// Valor del atributo `contentType`.
    pub fn content_type(&self) -> Option<Oid> {
        self.signed_attr(oids::CONTENT_TYPE)?.first_value()?.as_oid().ok()
    }

    /// Emisor (codificación original) y número de serie (complemento a dos)
    /// si el identificador es `IssuerAndSerialNumber`.
    pub fn issuer_and_serial(&self) -> Option<(&'a [u8], &'a [u8])> {
        if self.sid.tag != tags::SEQUENCE {
            return None;
        }
        let parts = self.sid.children().ok()?;
        let issuer = parts.first()?.raw;
        let serial = parts.get(1)?.as_integer_bytes().ok()?;
        Some((issuer, serial))
    }

    /// Identificador de clave del titular si el `sid` es `[0] SubjectKeyIdentifier`.
    pub fn subject_key_identifier(&self) -> Option<&'a [u8]> {
        (self.sid.tag.class == Class::Context && self.sid.tag.number == 0).then_some(self.sid.value)
    }

    /// Contrafirmas directas (valores de los atributos `counterSignature` que
    /// son SignerInfo válidos).
    pub fn counter_signatures(&self) -> Vec<SignerInfo<'a>> {
        let mut out = Vec::new();
        for attr in self.unsigned_attributes().unwrap_or_default() {
            if attr.is(oids::COUNTER_SIGNATURE) {
                for v in &attr.values {
                    if let Ok(si) = SignerInfo::parse(*v) {
                        out.push(si);
                    }
                }
            }
        }
        out
    }

    /// Sellos de tiempo de firma (`signatureTimeStampToken`), en DER.
    pub fn timestamp_tokens(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for attr in self.unsigned_attributes().unwrap_or_default() {
            if attr.is(oids::SIGNATURE_TIMESTAMP_TOKEN) {
                out.extend(attr.values.iter().map(Tlv::to_definite));
            }
        }
        out
    }
}

/// `SignedData` leído de un `ContentInfo`.
#[derive(Debug, Clone)]
pub struct SignedData<'a> {
    /// `ContentInfo` completo.
    pub content_info: Tlv<'a>,
    /// La SEQUENCE `SignedData`.
    pub signed_data: Tlv<'a>,
    pub version: i64,
    pub digest_algorithms: Tlv<'a>,
    pub encap_content_info: Tlv<'a>,
    pub econtent_type: Oid,
    /// El `OCTET STRING` del contenido firmado (si es implícita).
    pub econtent: Option<Tlv<'a>>,
    /// `[0] IMPLICIT CertificateSet`.
    pub certificates: Option<Tlv<'a>>,
    /// `[1] IMPLICIT RevocationInfoChoices`.
    pub crls: Option<Tlv<'a>>,
    pub signer_infos_set: Tlv<'a>,
    pub signer_infos: Vec<SignerInfo<'a>>,
}

/// Lee un `ContentInfo` y devuelve su tipo y su contenido (`[0] EXPLICIT`).
/// Como `ASN1InputStream.readObject`, se ignoran los datos posteriores.
pub fn parse_content_info(input: &[u8]) -> Result<(Oid, Option<Tlv<'_>>, Tlv<'_>)> {
    let (ci, _) = Tlv::parse(input)?;
    let ci = ci.expect(tags::SEQUENCE)?;
    let parts = ci.children()?;
    let oid = parts.first().ok_or(Asn1Error::Truncated)?.as_oid()?;
    let content = match parts.get(1) {
        Some(t) if t.tag.class == Class::Context && t.tag.number == 0 && t.tag.constructed => {
            Some(t.children()?.into_iter().next().ok_or(Asn1Error::Truncated)?)
        }
        Some(_) => return Err(invalid("contenido del ContentInfo no etiquetado")),
        None => None,
    };
    Ok((oid, content, ci))
}

impl<'a> SignedData<'a> {
    /// Lee un `ContentInfo` de tipo `signedData`.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        let (oid, content, ci) = parse_content_info(input)?;
        if !oid.is(oids::SIGNED_DATA) {
            return Err(invalid(format!("el ContentInfo no es SignedData sino {oid}")));
        }
        let sd = content.ok_or_else(|| invalid("SignedData sin contenido"))?;
        Self::parse_signed_data(ci, sd)
    }

    /// Lee la SEQUENCE `SignedData` (sin el `ContentInfo`).
    pub fn parse_signed_data(content_info: Tlv<'a>, sd: Tlv<'a>) -> Result<Self> {
        let sd = sd.expect(tags::SEQUENCE)?;
        let mut it = sd.children()?.into_iter();
        let version = it.next().ok_or(Asn1Error::Truncated)?.as_i64()?;
        let digest_algorithms = it.next().ok_or(Asn1Error::Truncated)?;
        if !digest_algorithms.tag.same_number(tags::SET) {
            return Err(invalid("digestAlgorithms no es un SET"));
        }
        let encap = it.next().ok_or(Asn1Error::Truncated)?.expect(tags::SEQUENCE)?;
        let encap_parts = encap.children()?;
        let econtent_type = encap_parts.first().ok_or(Asn1Error::Truncated)?.as_oid()?;
        let econtent = match encap_parts.get(1) {
            Some(t) if t.tag.class == Class::Context && t.tag.number == 0 => t.children()?.into_iter().next(),
            Some(_) => return Err(invalid("eContent mal etiquetado")),
            None => None,
        };
        let mut certificates = None;
        let mut crls = None;
        let mut signer_infos_set = None;
        for t in it {
            match (t.tag.class, t.tag.number) {
                (Class::Context, 0) => certificates = Some(t),
                (Class::Context, 1) => crls = Some(t),
                (Class::Universal, 17) => signer_infos_set = Some(t),
                _ => return Err(invalid(format!("elemento inesperado en SignedData: {}", t.tag))),
            }
        }
        let signer_infos_set = signer_infos_set.ok_or_else(|| invalid("SignedData sin signerInfos"))?;
        let signer_infos =
            signer_infos_set.children()?.into_iter().map(SignerInfo::parse).collect::<Result<Vec<_>>>()?;
        Ok(SignedData {
            content_info,
            signed_data: sd,
            version,
            digest_algorithms,
            encap_content_info: encap,
            econtent_type,
            econtent,
            certificates,
            crls,
            signer_infos_set,
            signer_infos,
        })
    }

    /// Contenido firmado (concatenando los segmentos si era un OCTET STRING
    /// construido en BER).
    pub fn content(&self) -> Option<Vec<u8>> {
        self.econtent.as_ref().and_then(|t| t.flatten_content().ok())
    }

    /// Elementos del conjunto `certificates` (cualquier tipo de elección).
    pub fn certificate_choices(&self) -> Vec<Tlv<'a>> {
        self.certificates.as_ref().and_then(|c| c.children().ok()).unwrap_or_default()
    }

    /// Certificados X.509 (DER original) del conjunto `certificates`.
    pub fn certificates_der(&self) -> Vec<&'a [u8]> {
        self.certificate_choices().into_iter().filter(|t| t.tag == tags::SEQUENCE).map(|t| t.raw).collect()
    }

    /// Primer certificado cuyo número de serie coincide (sin mirar el
    /// emisor, como AutoFirma).
    pub fn find_certificate_by_serial(&self, serial: &[u8]) -> Option<&'a [u8]> {
        self.certificates_der()
            .into_iter()
            .find(|c| CertView::parse(c).map(|v| v.serial_equals(serial)).unwrap_or(false))
    }

    /// Certificado de un firmante (por número de serie o por SKI).
    pub fn signer_certificate(&self, si: &SignerInfo<'_>) -> Option<&'a [u8]> {
        if let Some((_, serial)) = si.issuer_and_serial() {
            return self.find_certificate_by_serial(serial);
        }
        let ski = si.subject_key_identifier()?;
        self.certificates_der()
            .into_iter()
            .find(|c| CertView::parse(c).ok().and_then(|v| v.subject_key_identifier()).as_deref() == Some(ski))
    }

    /// Todos los SignerInfo (firmas y contrafirmas) en preorden.
    pub fn all_signer_infos(&self) -> Vec<SignerInfo<'a>> {
        fn walk<'a>(si: &SignerInfo<'a>, out: &mut Vec<SignerInfo<'a>>) {
            out.push(si.clone());
            for c in si.counter_signatures() {
                walk(&c, out);
            }
        }
        let mut out = Vec::new();
        for si in &self.signer_infos {
            walk(si, &mut out);
        }
        out
    }

    /// Indica si hay CRL u otra información de revocación.
    pub fn has_crls(&self) -> bool {
        self.crls.as_ref().and_then(|c| c.children().ok()).is_some_and(|v| !v.is_empty())
    }
}

/// Versión de un `SignerInfo`: 3 si el identificador es una SKI, 1 si no.
pub fn signer_info_version(sid: &[u8]) -> i64 {
    if sid.first().is_some_and(|b| b & 0xc0 == 0x80) { 3 } else { 1 }
}

/// Codifica un `SignerInfo`.
///
/// * `signed_attrs_set`: atributos firmados como `SET` (0x31) en DER; se
///   escriben con la etiqueta `[0] IMPLICIT`.
/// * `unsigned_attrs`: atributos no firmados ya codificados; se escriben
///   como `[1] IMPLICIT SET` ordenado.
pub fn encode_signer_info(
    sid: &[u8],
    digest_algorithm: &[u8],
    signed_attrs_set: Option<&[u8]>,
    signature_algorithm: &[u8],
    signature: &[u8],
    unsigned_attrs: Option<&[Vec<u8>]>,
) -> Vec<u8> {
    let tagged = signed_attrs_set.map(|sa| match Tlv::parse_single(sa) {
        Ok(t) => der::implicit_content(0, true, t.value),
        Err(_) => der::implicit_content(0, true, &[]),
    });
    encode_signer_info_raw(sid, digest_algorithm, tagged.as_deref(), signature_algorithm, signature, unsigned_attrs)
}

/// Como [`encode_signer_info`] pero con los atributos firmados ya
/// codificados con su etiqueta `[0] IMPLICIT` (p. ej. copiados de una firma
/// existente).
pub fn encode_signer_info_raw(
    sid: &[u8],
    digest_algorithm: &[u8],
    signed_attrs_tagged: Option<&[u8]>,
    signature_algorithm: &[u8],
    signature: &[u8],
    unsigned_attrs: Option<&[Vec<u8>]>,
) -> Vec<u8> {
    let mut parts = vec![der::integer_i64(signer_info_version(sid)), sid.to_vec(), digest_algorithm.to_vec()];
    if let Some(sa) = signed_attrs_tagged {
        parts.push(sa.to_vec());
    }
    parts.push(signature_algorithm.to_vec());
    parts.push(der::octet_string(signature));
    if let Some(ua) = unsigned_attrs {
        parts.push(der::implicit_content(1, true, &der::sorted_concat(ua)));
    }
    der::sequence(parts)
}

/// Reconstruye un `SignerInfo` existente con otros atributos no firmados
/// (como `new SignerInfo(si.getSID(), ...)` de Bouncy Castle: la versión se
/// recalcula y el resto de campos se copian).
pub fn rebuild_signer_info(si: &SignerInfo<'_>, unsigned_attrs: Option<&[Vec<u8>]>) -> Vec<u8> {
    let signed = si.signed_attrs.as_ref().map(to_der_preserving);
    encode_signer_info_raw(
        &to_der_preserving(&si.sid),
        &to_der_preserving(&si.digest_algorithm),
        signed.as_deref(),
        &to_der_preserving(&si.signature_algorithm),
        &si.signature_value(),
        unsigned_attrs,
    )
}

/// Elementos de `digestAlgorithms` con el algoritmo de un nuevo firmante
/// añadido si no estaba (AutoFirma no lo añade, lo que impide verificar con
/// OpenSSL las cofirmas con otra huella; ver `docs/deviations/afirma-cms.md`).
pub fn digest_algorithms_with(existing: &Tlv<'_>, new_alg_id: &[u8]) -> Vec<Vec<u8>> {
    let mut algs = set_elements_der(existing);
    let new_oid = Tlv::parse_single(new_alg_id)
        .ok()
        .and_then(|t| t.children().ok())
        .and_then(|c| c.first().map(|o| o.raw.to_vec()));
    let present = algs.iter().any(|a| {
        Tlv::parse_single(a).ok().and_then(|t| t.children().ok()).and_then(|c| c.first().map(|o| o.raw.to_vec()))
            == new_oid
    });
    if !present {
        algs.push(new_alg_id.to_vec());
    }
    algs
}

/// Versión de `SignedData` según RFC 5652 §5.1 (como el constructor de
/// `SignedData` de Bouncy Castle).
pub fn signed_data_version(
    certificates: &[Vec<u8>],
    crls: &[Vec<u8>],
    signer_info_versions: &[i64],
    econtent_type: &str,
) -> i64 {
    let tag_no = |c: &Vec<u8>| -> Option<u8> { c.first().filter(|b| *b & 0xc0 == 0x80).map(|b| b & 0x1f) };
    let mut other_cert = false;
    let mut attr_v1 = false;
    let mut attr_v2 = false;
    for c in certificates {
        match tag_no(c) {
            Some(1) => attr_v1 = true,
            Some(2) => attr_v2 = true,
            Some(3) => other_cert = true,
            _ => {}
        }
    }
    if other_cert || crls.iter().any(|c| tag_no(c).is_some()) {
        return 5;
    }
    if attr_v2 {
        return 4;
    }
    if attr_v1 || signer_info_versions.contains(&3) || econtent_type != oids::DATA {
        return 3;
    }
    1
}

/// Partes de un `SignedData` para su codificación.
#[derive(Debug, Clone, Default)]
pub struct SignedDataParts {
    /// Elementos del SET `digestAlgorithms` (DER).
    pub digest_algorithms: Vec<Vec<u8>>,
    /// `EncapsulatedContentInfo` completo (DER).
    pub encap_content_info: Vec<u8>,
    /// Certificados (`None` omite el campo).
    pub certificates: Option<Vec<Vec<u8>>>,
    /// CRL (`None` omite el campo).
    pub crls: Option<Vec<Vec<u8>>>,
    /// SignerInfo (DER).
    pub signer_infos: Vec<Vec<u8>>,
}

impl SignedDataParts {
    /// Codifica el `ContentInfo { signedData, [0] SignedData }` en DER.
    pub fn encode(&self) -> Vec<u8> {
        let econtent_type = Tlv::parse_single(&self.encap_content_info)
            .ok()
            .and_then(|t| t.children().ok())
            .and_then(|c| c.first().and_then(|o| o.as_oid().ok()))
            .map(|o| o.to_dotted())
            .unwrap_or_else(|| oids::DATA.to_string());
        let si_versions: Vec<i64> = self
            .signer_infos
            .iter()
            .filter_map(|s| Tlv::parse_single(s).ok().and_then(|t| t.children().ok()))
            .filter_map(|c| c.first().and_then(|v| v.as_i64().ok()))
            .collect();
        let version = signed_data_version(
            self.certificates.as_deref().unwrap_or(&[]),
            self.crls.as_deref().unwrap_or(&[]),
            &si_versions,
            &econtent_type,
        );
        let mut parts =
            vec![der::integer_i64(version), der::set_of(&self.digest_algorithms), self.encap_content_info.clone()];
        if let Some(c) = &self.certificates {
            parts.push(der::implicit_content(0, true, &der::sorted_concat(c)));
        }
        if let Some(c) = &self.crls {
            parts.push(der::implicit_content(1, true, &der::sorted_concat(c)));
        }
        parts.push(der::set_of(&self.signer_infos));
        content_info(oids::SIGNED_DATA, &der::sequence(parts))
    }
}

/// `ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT content }`.
pub fn content_info(oid: &str, content: &[u8]) -> Vec<u8> {
    der::sequence([der::oid_str(oid), der::explicit(0, content)])
}

/// `EncapsulatedContentInfo` de tipo `id-data` con el contenido (si lo hay)
/// como OCTET STRING primitivo.
pub fn encap_content_info(content: Option<&[u8]>) -> Vec<u8> {
    match content {
        Some(c) => der::sequence([der::oid_str(oids::DATA), der::explicit(0, &der::octet_string(c))]),
        None => der::sequence([der::oid_str(oids::DATA)]),
    }
}

/// Convierte un elemento BER a DER "conservador": longitudes definidas y
/// cadenas construidas (OCTET STRING, BIT STRING, cadenas de texto) aplanadas
/// a su forma primitiva. No reordena los SET (eso alteraría las firmas de
/// terceros cuyos atributos no estuvieran ordenados).
pub fn to_der_preserving(t: &Tlv<'_>) -> Vec<u8> {
    let is_string = t.tag.class == Class::Universal
        && t.tag.constructed
        && matches!(t.tag.number, 3 | 4 | 12 | 18 | 19 | 20 | 22 | 26 | 28 | 30);
    if is_string {
        if let Ok(content) = t.flatten_content() {
            if t.tag.number == 3 {
                // BIT STRING construido: los segmentos llevan su byte de bits
                // sobrantes; se conserva solo el del último.
                return der::bit_string(&content);
            }
            return der::tlv(t.tag.with_constructed(false), &content);
        }
    }
    if !t.tag.constructed {
        return t.raw.to_vec();
    }
    if !t.indefinite && !contains_indefinite_or_constructed_string(t) {
        return t.raw.to_vec();
    }
    let mut content = Vec::new();
    if let Ok(children) = t.children() {
        for c in children {
            content.extend(to_der_preserving(&c));
        }
    }
    der::tlv(t.tag, &content)
}

fn contains_indefinite_or_constructed_string(t: &Tlv<'_>) -> bool {
    let Ok(children) = t.children() else { return false };
    children.iter().any(|c| {
        c.indefinite
            || (c.tag.class == Class::Universal
                && c.tag.constructed
                && matches!(c.tag.number, 3 | 4 | 12 | 18 | 19 | 20 | 22 | 26 | 28 | 30))
            || (c.tag.constructed && contains_indefinite_or_constructed_string(c))
    })
}

/// Bytes de un SET/`[n] IMPLICIT SET` convertido en una lista de elementos DER.
pub fn set_elements_der(t: &Tlv<'_>) -> Vec<Vec<u8>> {
    t.children().map(|c| c.iter().map(to_der_preserving).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(signed_data_version(&[vec![0x30, 0x00]], &[], &[1], oids::DATA), 1);
        assert_eq!(signed_data_version(&[vec![0x30, 0x00]], &[], &[1, 3], oids::DATA), 3);
        assert_eq!(signed_data_version(&[vec![0xa3, 0x00]], &[], &[1], oids::DATA), 5);
        assert_eq!(signed_data_version(&[], &[vec![0xa1, 0x00]], &[1], oids::DATA), 5);
        assert_eq!(signed_data_version(&[vec![0xa2, 0x00]], &[], &[1], oids::DATA), 4);
        assert_eq!(signed_data_version(&[], &[], &[1], "1.2.840.113549.1.9.16.1.4"), 3);
    }

    #[test]
    fn ber_to_der() {
        // SEQUENCE indefinida con un OCTET STRING construido.
        let ber = [0x30, 0x80, 0x24, 0x80, 0x04, 0x01, 0x61, 0x04, 0x01, 0x62, 0x00, 0x00, 0x00, 0x00];
        let (t, _) = Tlv::parse(&ber).unwrap();
        assert_eq!(to_der_preserving(&t), vec![0x30, 0x04, 0x04, 0x02, 0x61, 0x62]);
        // Un SET desordenado no se reordena.
        let set = [0x31, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x01];
        let (t, _) = Tlv::parse(&set).unwrap();
        assert_eq!(to_der_preserving(&t), set.to_vec());
    }
}
