//! Sellos de tiempo RFC 3161.
//!
//! El cliente (petición, transporte HTTP(S)/`socket://`, validación de la
//! respuesta y CAdES-T) es el de `afirma-cms` ([`afirma_cms::tsp`]); aquí se
//! reexporta y se añade una TSA local para pruebas.

use std::sync::Arc;

use afirma_cms::asn1::{Tlv, der, tags};
use afirma_core::DigestAlgorithm;

pub use afirma_cms::tsp::transport::{DefaultTransport, TsaTransport};
pub use afirma_cms::tsp::{Timestamper, TsaParams};

/// Política por defecto de AutoFirma.
pub const DEFAULT_TSA_POLICY: &str = "0.4.0.2023.1.1";

/// Transporte compartido (adaptador de `Arc` a la caja que pide
/// [`Timestamper::with_transport`]).
#[derive(Clone)]
pub struct SharedTransport(pub Arc<dyn TsaTransport>);

impl TsaTransport for SharedTransport {
    fn send(&self, params: &TsaParams, request: &[u8]) -> Result<Vec<u8>, String> {
        self.0.send(params, request)
    }
}

/// TSA local para pruebas: firma los sellos con una clave RSA en memoria.
pub mod mock {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;

    /// TSA de pruebas.
    pub struct MockTsa {
        key: rsa::RsaPrivateKey,
        cert: Vec<u8>,
        /// Fecha que se pone en los sellos.
        pub time: chrono::DateTime<chrono::Utc>,
    }

    impl MockTsa {
        /// `key_pem`: clave PKCS#8 en PEM; `cert`: certificado DER.
        pub fn new(key_pem: &str, cert: Vec<u8>) -> Option<MockTsa> {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem).ok()?;
            Some(MockTsa {
                key,
                cert,
                time: chrono::Utc::now(),
            })
        }
    }

    impl TsaTransport for MockTsa {
        fn send(&self, _params: &TsaParams, request: &[u8]) -> Result<Vec<u8>, String> {
            let err = |e: &str| format!("TSA de pruebas: {e}");
            let req = Tlv::parse_single(request).map_err(|e| err(&e.to_string()))?;
            let f = req.children().map_err(|e| err(&e.to_string()))?;
            let imprint = f.get(1).ok_or_else(|| err("sin imprint"))?.to_definite();
            let nonce = f
                .iter()
                .skip(2)
                .find(|t| t.tag == tags::INTEGER)
                .map(|t| t.to_definite());
            let mut tst = vec![
                der::integer_i64(1),
                der::oid_str(DEFAULT_TSA_POLICY),
                imprint,
                der::integer_i64(
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(1) & 0x7fff_ffff,
                ),
                der::generalized_time(&self.time, false),
            ];
            if let Some(n) = nonce {
                tst.push(n);
            }
            let tst = der::sequence(tst);
            let digest = DigestAlgorithm::Sha256;
            let cert_hash = digest.digest(&self.cert);
            let parts = crate::cms::cert_parts(&self.cert).map_err(|e| err(&e.to_string()))?;
            let ess = der::sequence([der::octet_string(&cert_hash)]);
            let attrs = der::set_of([
                der::sequence([
                    der::oid_str(crate::cms::OID_CONTENT_TYPE),
                    der::set_of([der::oid_str(crate::cms::OID_TST_INFO)]),
                ]),
                der::sequence([
                    der::oid_str(crate::cms::OID_MESSAGE_DIGEST),
                    der::set_of([der::octet_string(&digest.digest(&tst))]),
                ]),
                der::sequence([
                    der::oid_str(crate::cms::OID_SIGNING_CERTIFICATE_V2),
                    der::set_of([der::sequence([der::sequence([ess])])]),
                ]),
            ]);
            let hash = digest.digest(&attrs);
            let sig = self
                .key
                .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hash)
                .map_err(|e| err(&e.to_string()))?;
            let sid = der::sequence([parts.issuer.clone(), der::integer_raw(&parts.serial)]);
            let attrs_tlv = Tlv::parse_single(&attrs).map_err(|e| err(&e.to_string()))?;
            let si = der::sequence([
                der::integer_i64(1),
                sid,
                der::sequence([der::oid_str(digest.oid()), der::null()]),
                attrs_tlv.retagged_raw(afirma_cms::asn1::Tag::context(0, true)),
                der::sequence([der::oid_str(crate::cms::OID_RSA_ENCRYPTION), der::null()]),
                der::octet_string(&sig),
            ]);
            let sd = der::sequence([
                der::integer_i64(3),
                der::set_of([der::sequence([der::oid_str(digest.oid()), der::null()])]),
                der::sequence([
                    der::oid_str(crate::cms::OID_TST_INFO),
                    der::explicit(0, &der::octet_string(&tst)),
                ]),
                der::implicit_content(0, true, &self.cert),
                der::set_of([si]),
            ]);
            let token = der::sequence([
                der::oid_str(crate::cms::OID_SIGNED_DATA),
                der::explicit(0, &sd),
            ]);
            Ok(der::sequence([der::sequence([der::integer_i64(0)]), token]))
        }
    }
}
