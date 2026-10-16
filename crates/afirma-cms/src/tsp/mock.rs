//! Autoridad de sellado de tiempo de pruebas, en proceso.
//!
//! Responde a peticiones `TimeStampReq` con sellos firmados por una clave
//! cualquiera ([`SigningKey`]) y puede servirlas por HTTP o por el protocolo
//! `socket://` en un puerto local para probar el cliente de extremo a extremo.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;

use afirma_core::algorithms::{DigestAlgorithm, SignatureAlgorithm};
use afirma_core::key::SigningKey;
use chrono::{DateTime, SubsecRound, Utc};

use crate::alg;
use crate::asn1::{Tlv, der, tags};
use crate::cades::attrs;
use crate::cert::CertView;
use crate::cms::{self, SignedDataParts, encode_signer_info};
use crate::oids;

/// Política que asigna la TSA de pruebas si la petición no indica ninguna.
pub const MOCK_POLICY: &str = "1.3.6.1.4.1.99999.1";

/// Comportamientos anómalos para probar la validación del cliente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Misbehavior {
    #[default]
    None,
    /// Devuelve otro nonce.
    WrongNonce,
    /// Sella otra huella.
    WrongImprint,
    /// Responde con estado `rejection` (2) y sin token.
    Reject,
    /// Corrompe la firma del sello.
    BadSignature,
}

/// TSA de pruebas.
pub struct MockTsa {
    key: Box<dyn SigningKey>,
    serial: AtomicU64,
    pub misbehavior: Misbehavior,
    /// Instante fijo de los sellos (si no, la hora actual).
    pub fixed_time: Option<DateTime<Utc>>,
}

impl MockTsa {
    pub fn new(key: Box<dyn SigningKey>) -> Self {
        MockTsa { key, serial: AtomicU64::new(1), misbehavior: Misbehavior::None, fixed_time: None }
    }

    /// Procesa una petición y devuelve la respuesta `TimeStampResp` (DER).
    pub fn respond(&self, request: &[u8]) -> Vec<u8> {
        match self.try_respond(request) {
            Ok(r) => r,
            Err(_) => reject(2, 5),
        }
    }

    fn try_respond(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        if self.misbehavior == Misbehavior::Reject {
            return Ok(reject(2, 0));
        }
        let req = Tlv::parse_single(request).map_err(|e| e.to_string())?;
        let f = req.children().map_err(|e| e.to_string())?;
        let mi = f.get(1).ok_or("sin messageImprint")?;
        let mut mi_der = mi.raw.to_vec();
        let mut policy: Option<Vec<u8>> = None;
        let mut nonce: Option<Vec<u8>> = None;
        let mut cert_req = false;
        for t in f.iter().skip(2) {
            if t.tag == tags::OID {
                policy = Some(t.raw.to_vec());
            } else if t.tag == tags::INTEGER {
                nonce = Some(t.value.to_vec());
            } else if t.tag == tags::BOOLEAN {
                cert_req = t.as_bool().unwrap_or(false);
            }
        }
        if self.misbehavior == Misbehavior::WrongImprint {
            let parts = mi.children().map_err(|e| e.to_string())?;
            let mut imprint = parts.get(1).and_then(|o| o.octet_string_content().ok()).unwrap_or_default();
            if let Some(b) = imprint.first_mut() {
                *b ^= 0xff;
            }
            let alg = parts.first().map(|p| p.raw.to_vec()).unwrap_or_default();
            mi_der = der::sequence([alg, der::octet_string(&imprint)]);
        }
        if self.misbehavior == Misbehavior::WrongNonce {
            nonce = Some(vec![0x01, 0x02, 0x03]);
        }
        let now = self.fixed_time.unwrap_or_else(|| Utc::now().trunc_subsecs(0));
        let serial = self.serial.fetch_add(1, Ordering::SeqCst);
        let mut tst = vec![
            der::integer_i64(1),
            policy.unwrap_or_else(|| der::oid_str(MOCK_POLICY)),
            mi_der,
            der::integer_unsigned(&serial.to_be_bytes()),
            der::generalized_time(&now, false),
        ];
        if let Some(n) = nonce {
            tst.push(der::integer_raw(&n));
        }
        let tst_info = der::sequence(tst);
        let token = self.sign_token(&tst_info, cert_req, now)?;
        Ok(der::sequence([der::sequence([der::integer_i64(0)]), token]))
    }

    fn sign_token(&self, tst_info: &[u8], cert_req: bool, now: DateTime<Utc>) -> Result<Vec<u8>, String> {
        let cert = self.key.certificate().to_vec();
        let view = CertView::parse(&cert).map_err(|e| e.to_string())?;
        let digest = DigestAlgorithm::Sha256;
        let signed_attrs = vec![
            cms::encode_attribute(oids::CONTENT_TYPE, &[der::oid_str(oids::TST_INFO)]),
            cms::encode_attribute(oids::SIGNING_TIME, &[der::utc_time(&now)]),
            cms::encode_attribute(oids::MESSAGE_DIGEST, &[der::octet_string(&digest.digest(tst_info))]),
            attrs::signing_certificate_v2(&view, digest, false, true),
        ];
        let set = attrs::attributes_set(&signed_attrs);
        let alg = SignatureAlgorithm::new(digest, self.key.key_algorithm());
        let mut sig = self.key.sign(&set, alg).map_err(|e| e.to_string())?;
        if self.misbehavior == Misbehavior::BadSignature {
            if let Some(b) = sig.last_mut() {
                *b ^= 0x01;
            }
        }
        let si = encode_signer_info(
            &view.issuer_and_serial(),
            &alg::digest_alg_id(digest),
            Some(&set),
            &alg::alg_id_null(alg::signature_oid(alg)),
            &sig,
            None,
        );
        let encap = der::sequence([der::oid_str(oids::TST_INFO), der::explicit(0, &der::octet_string(tst_info))]);
        Ok(SignedDataParts {
            digest_algorithms: vec![alg::digest_alg_id(digest)],
            encap_content_info: encap,
            certificates: cert_req.then(|| self.key.certificate_chain()),
            crls: None,
            signer_infos: vec![si],
        }
        .encode())
    }

    /// Sirve peticiones HTTP en `127.0.0.1` (puerto libre) en un hilo.
    /// Devuelve la URL y el hilo. Si `basic_auth` es `Some`, exige esa
    /// cabecera `Authorization`.
    pub fn serve_http(self: Arc<Self>, max_requests: usize, basic_auth: Option<String>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("no se pudo abrir un puerto local");
        let url = format!("http://{}/tsa", listener.local_addr().expect("dirección local"));
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(max_requests) {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().expect("socket"));
                let mut content_length = 0usize;
                let mut auth = None;
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let l = line.trim_end();
                    if l.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = l.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            content_length = v.trim().parse().unwrap_or(0);
                        } else if k.eq_ignore_ascii_case("authorization") {
                            auth = Some(v.trim().to_string());
                        }
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                let (status, resp) = if basic_auth.is_some() && auth != basic_auth {
                    ("401 Unauthorized", Vec::new())
                } else {
                    ("200 OK", self.respond(&body))
                };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&resp);
                let _ = stream.flush();
            }
        });
        (url, handle)
    }

    /// Sirve peticiones con el protocolo `socket://` de AutoFirma.
    pub fn serve_socket(self: Arc<Self>, max_requests: usize) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("no se pudo abrir un puerto local");
        let url = format!("socket://{}", listener.local_addr().expect("dirección local"));
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(max_requests) {
                let Ok(mut stream) = stream else { continue };
                let mut hdr = [0u8; 5];
                if stream.read_exact(&mut hdr).is_err() {
                    continue;
                }
                let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                let mut body = vec![0u8; len.saturating_sub(1)];
                if stream.read_exact(&mut body).is_err() {
                    continue;
                }
                let resp = self.respond(&body);
                let mut out = ((resp.len() + 1) as u32).to_be_bytes().to_vec();
                out.push(5);
                out.extend(resp);
                let _ = stream.write_all(&out);
            }
        });
        (url, handle)
    }
}

/// Respuesta de rechazo con el estado y el `failInfo` indicados.
fn reject(status: i64, fail_bit: u8) -> Vec<u8> {
    let mut info = vec![der::integer_i64(status), der::sequence([der::utf8_string("rechazado")])];
    if fail_bit > 0 {
        info.push(der::tlv(tags::BIT_STRING, &[0x00, 1u8 << (7 - (fail_bit % 8))]));
    }
    der::sequence([der::sequence(info)])
}
