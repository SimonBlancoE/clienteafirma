//! Sello de tiempo XAdES-T (`XAdESTspUtil.timestampXAdES`): se sella el
//! primer `ds:SignatureValue` del documento y se añade un
//! `UnsignedProperties/UnsignedSignatureProperties/SignatureTimeStamp` nuevo a
//! las primeras `QualifyingProperties` (espacio de nombres 1.3.2).

use afirma_cms::tsp::{Timestamper, TsaParams};
use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;

use crate::c14n::{C14n, Kind};
use crate::dom::Document;
use crate::dsig::DSIG_NS;
use crate::splice;
use crate::util::b64;

use super::NS_XADES_132;

/// Añade el sello si los parámetros incluyen `tsaURL` (si los parámetros de
/// la TSA no son válidos no se sella, como en Java).
pub fn timestamp_if_requested(signed: Vec<u8>, extra: &ExtraParams) -> afirma_core::Result<Vec<u8>> {
    let params = match TsaParams::from_extra_params(extra) {
        Ok(Some(p)) => p,
        Ok(None) => return Ok(signed),
        Err(e) => {
            tracing::warn!("Parametros de sellado de tiempo no validos, no se sellara la firma: {e}");
            return Ok(signed);
        }
    };
    timestamp_with(&signed, &Timestamper::new(params))
}

/// Huella a sellar: C14N del primer `ds:SignatureValue` convertido de forma
/// aislada (solo su propia declaración de espacio de nombres, como XOM).
pub fn signature_value_imprint_input(doc: &Document) -> afirma_core::Result<Vec<u8>> {
    let sv = doc
        .find_descendants(doc.root(), DSIG_NS, "SignatureValue")
        .into_iter()
        .next()
        .ok_or_else(|| AfirmaError::new(codes::TSA_CONNECTION_ERROR, "El XML no tiene nodo de firma"))?;
    Ok(C14n::new(Kind::Exclusive, false).canonicalize(doc, sv, &[]))
}

/// Sella la firma con el cliente indicado.
pub fn timestamp_with(signed: &[u8], ts: &Timestamper) -> afirma_core::Result<Vec<u8>> {
    let (doc, _) = Document::parse_bytes(signed).map_err(|e| {
        AfirmaError::invalid_signature_format(format!(
            "No se puede analizar la firma para agregar el sello de tiempo: {e}"
        ))
    })?;
    let qps = doc.find_descendants(doc.root(), NS_XADES_132, "QualifyingProperties");
    let Some(&qp) = qps.first() else {
        return Err(AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            "La firma no tiene 'QualifyingProperties', no se puede aplicar el sello de tiempo",
        ));
    };
    if qps.len() > 1 {
        tracing::warn!("El XML tiene mas de una firma, solo se sellara la primera");
    }
    let input = signature_value_imprint_input(&doc)?;
    let alg = ts.params.hash_algorithm;
    let token = ts.get_timestamp_token(&alg.digest(&input), alg)?;
    let fragment = format!(
        "<xades:UnsignedProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">\n <xades:UnsignedSignatureProperties>\n  <xades:SignatureTimeStamp>\n   <ds:CanonicalizationMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n   <xades:EncapsulatedTimeStamp>\n{}</xades:EncapsulatedTimeStamp>\n  </xades:SignatureTimeStamp>\n </xades:UnsignedSignatureProperties>\n</xades:UnsignedProperties>",
        b64(&token)
    );
    let text = splice::insert_last_child(&doc, qp, &fragment);
    let encoding = doc
        .xml_decl
        .as_ref()
        .and_then(|d| d.encoding.clone())
        .unwrap_or_else(|| "UTF-8".into());
    splice::finish_preserving(&doc, &text, &encoding).map_err(|m| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, m))
}
