//! Cliente RFC 3161 contra la TSA de pruebas en proceso (HTTP y socket),
//! CAdES-T y verificación cruzada con `openssl ts`.

mod common;

use std::sync::Arc;

use afirma_cms::cms::SignedData;
use afirma_cms::tsp::mock::{Misbehavior, MockTsa};
use afirma_cms::tsp::{self, Timestamper, TsaParams};
use afirma_cms::{CadesSigner, inspect, oids, validation};
use afirma_core::algorithms::DigestAlgorithm;
use afirma_core::error::codes;
use afirma_core::validity::{Validity, ValidityError};
use afirma_core::{ExtraParams, Signer};
use common::*;

fn mock(m: Misbehavior) -> Arc<MockTsa> {
    let mut t = MockTsa::new(Box::new(key("tsa")));
    t.misbehavior = m;
    Arc::new(t)
}

#[test]
fn token_over_http_is_valid_and_verifiable() {
    let (url, h) = mock(Misbehavior::None).serve_http(1, None);
    let mut p = TsaParams::new(url);
    p.hash_algorithm = DigestAlgorithm::Sha256;
    let imprint = DigestAlgorithm::Sha256.digest(b"hola");
    let info = Timestamper::new(p).request_token(&imprint, DigestAlgorithm::Sha256).unwrap();
    h.join().unwrap();
    assert_eq!(info.imprint, imprint);
    assert_eq!(info.imprint_algorithm, DigestAlgorithm::Sha256.oid());
    assert_eq!(info.policy, oids::DEFAULT_TSA_POLICY);
    assert!(info.tsa_certificate.is_some());
    assert!(validation::verify_timestamp_token(&info.token));
}

#[test]
fn socket_transport_and_params() {
    let (url, h) = mock(Misbehavior::None).serve_socket(1);
    let mut extra = ExtraParams::new();
    extra.set("tsaURL", &url);
    extra.set("tsaPolicy", "1.2.3.4.5");
    extra.set("tsaHashAlgorithm", "SHA-384");
    extra.set("tsaRequireCert", "FALSE");
    let p = TsaParams::from_extra_params(&extra).unwrap().unwrap();
    assert_eq!(p.hash_algorithm, DigestAlgorithm::Sha384);
    assert!(!p.require_cert);
    let imprint = DigestAlgorithm::Sha384.digest(b"x");
    let info = Timestamper::new(p).request_token(&imprint, DigestAlgorithm::Sha384).unwrap();
    h.join().unwrap();
    assert_eq!(info.policy, "1.2.3.4.5");
    assert!(info.tsa_certificate.is_none(), "sin certReq no se incluye el certificado");
}

#[test]
fn basic_auth() {
    let expected = format!("Basic {}", afirma_core::base64_encode(b"usuario:clave"));
    let (url, h) = mock(Misbehavior::None).serve_http(2, Some(expected));
    let mut extra = ExtraParams::new();
    extra.set("tsaURL", &url);
    extra.set("tsaUsr", "usuario");
    extra.set("tsaPwd", "clave");
    let ts = Timestamper::new(TsaParams::from_extra_params(&extra).unwrap().unwrap());
    assert!(ts.get_timestamp_token(&[0u8; 64], DigestAlgorithm::Sha512).is_ok());
    extra.set("tsaPwd", "mala");
    let ts = Timestamper::new(TsaParams::from_extra_params(&extra).unwrap().unwrap());
    let e = ts.get_timestamp_token(&[0u8; 64], DigestAlgorithm::Sha512).unwrap_err();
    assert_eq!(e.code, Some(codes::TSA_CONNECTION_ERROR));
    h.join().unwrap();
}

#[test]
fn invalid_responses_are_rejected() {
    for m in [Misbehavior::WrongNonce, Misbehavior::WrongImprint, Misbehavior::Reject, Misbehavior::BadSignature] {
        let (url, h) = mock(m).serve_http(1, None);
        let e =
            Timestamper::new(TsaParams::new(url)).get_timestamp_token(&[1u8; 64], DigestAlgorithm::Sha512).unwrap_err();
        h.join().unwrap();
        assert_eq!(e.code, Some(codes::GENERATING_TIMESTAMP_ERROR), "{m:?}: {e}");
    }
    // Sin servidor: error de comunicación.
    let e = Timestamper::new(TsaParams::new("http://127.0.0.1:9/tsa"))
        .get_timestamp_token(&[1u8; 64], DigestAlgorithm::Sha512);
    assert_eq!(e.unwrap_err().code, Some(codes::TSA_CONNECTION_ERROR));
    let e = Timestamper::new(TsaParams::new("ftp://127.0.0.1/tsa"))
        .get_timestamp_token(&[1u8; 64], DigestAlgorithm::Sha512);
    assert_eq!(e.unwrap_err().code, Some(codes::TSA_CONNECTION_ERROR));
}

#[test]
fn request_encoding() {
    let ext = tsp::TsaRequestExtension { oid: "1.2.3".into(), critical: true, value: vec![0x05, 0x00] };
    let req =
        tsp::build_request(&[0xaa; 32], DigestAlgorithm::Sha256, Some("0.4.0.2023.1.1"), true, Some(&ext), 0x1234)
            .unwrap();
    // Estructura: versión 1, imprint con NULL, política, nonce, certReq y extensión [0].
    let t = afirma_cms::asn1::Tlv::parse_single(&req.der).unwrap();
    let f = t.children().unwrap();
    assert_eq!(f[0].as_i64().unwrap(), 1);
    assert_eq!(hex::encode(f[1].children().unwrap()[0].raw), "300d06096086480165030402010500");
    assert_eq!(f[2].as_oid().unwrap().to_dotted(), "0.4.0.2023.1.1");
    assert_eq!(f[3].value, &[0x12, 0x34]);
    assert!(f[4].as_bool().unwrap());
    assert_eq!(hex::encode(f[5].raw), "a00f300d300b06022a030101ff04020500");
    let req = tsp::build_request(&[0xaa; 32], DigestAlgorithm::Sha256, None, false, None, 1).unwrap();
    assert_eq!(afirma_cms::asn1::Tlv::parse_single(&req.der).unwrap().children().unwrap().len(), 3);
}

#[test]
fn openssl_ts_verify() {
    if !have_openssl() {
        return;
    }
    let tsa = mock(Misbehavior::None);
    let req = tsp::build_request(
        &DigestAlgorithm::Sha256.digest(b"datos"),
        DigestAlgorithm::Sha256,
        Some(oids::DEFAULT_TSA_POLICY),
        true,
        None,
        42,
    )
    .unwrap();
    let resp = tsa.respond(&req.der);
    let dir = tmpdir("ts");
    std::fs::write(dir.join("req.tsq"), &req.der).unwrap();
    std::fs::write(dir.join("resp.tsr"), &resp).unwrap();
    let out = std::process::Command::new("openssl")
        .args(["ts", "-verify", "-in"])
        .arg(dir.join("resp.tsr"))
        .arg("-queryfile")
        .arg(dir.join("req.tsq"))
        .arg("-CAfile")
        .arg(testdata("pki/ca.crt"))
        .arg("-untrusted")
        .arg(testdata("pki/tsa.crt"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("Verification: OK"), "{text}");
}

#[test]
fn cades_t_signature() {
    let (url, h) = mock(Misbehavior::None).serve_http(1, None);
    let mut extra = ExtraParams::new();
    extra.set("mode", "implicit");
    extra.set("tsaURL", &url);
    extra.set("tsaHashAlgorithm", "SHA-256");
    let sign = CadesSigner.sign(b"Hola mundo", "SHA256withRSA", &key("firmante-rsa"), &extra).unwrap();
    h.join().unwrap();
    let sd = SignedData::parse(&sign).unwrap();
    let si = &sd.signer_infos[0];
    let tokens = si.timestamp_tokens();
    assert_eq!(tokens.len(), 1);
    let info = tsp::parse_timestamp_token(&tokens[0]).unwrap();
    assert_eq!(info.imprint, DigestAlgorithm::Sha256.digest(&si.signature_value()));
    // Perfil T-Level: AutoFirma no lo valida por completo.
    let details = inspect::signers(&sign).unwrap();
    assert_eq!(details[0].profile, "CAdES T-Level");
    assert_eq!(details[0].timestamps.len(), 1);
    let v = validation::validate(&sign, None, true);
    assert_eq!(v.len(), 1);
    assert_eq!((v[0].validity, v[0].error), (Validity::Unknown, Some(ValidityError::SignProfileNotChecked)));
    if let Some((ok, msg)) = openssl_verify("cades_t", &sign, None) {
        assert!(ok, "{msg}");
    }
    // Escribe la firma para las pruebas cruzadas con Java si se pide.
    if let Ok(dir) = std::env::var("AFIRMA_CMS_DUMP") {
        std::fs::write(std::path::Path::new(&dir).join("rust_cades_t.csig"), &sign).unwrap();
    }
}

#[test]
fn no_tsa_url_no_timestamp() {
    let sign = CadesSigner.sign(b"x", "SHA256withRSA", &key("firmante-rsa"), &ExtraParams::new()).unwrap();
    assert!(SignedData::parse(&sign).unwrap().signer_infos[0].unsigned_attrs.is_none());
}

/// Respuesta con `Content-Encoding: base64` (se decodifica como en Java).
#[test]
fn base64_content_encoding() {
    use std::io::{BufRead, BufReader, Read, Write};
    let tsa = mock(Misbehavior::None);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsa", listener.local_addr().unwrap());
    let h = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut len = 0usize;
        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':')
                && k.eq_ignore_ascii_case("content-length") {
                    len = v.trim().parse().unwrap();
                }
        }
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).unwrap();
        let resp = afirma_core::base64_encode(&tsa.respond(&body));
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: base64\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            resp.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(resp.as_bytes()).unwrap();
    });
    let token = Timestamper::new(TsaParams::new(url)).get_timestamp_token(&[7u8; 64], DigestAlgorithm::Sha512);
    h.join().unwrap();
    assert!(token.is_ok(), "{:?}", token.err());
}
