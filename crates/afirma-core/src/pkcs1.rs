//! Firma PKCS#1 sin formato (`AOPkcs1Signer`, formato `NONE`) y su
//! variante trifásica (`AOPkcs1TriPhaseSigner`, formato `NONEtri`) (§3.2-3.3).

use std::sync::Arc;

use ring::signature as rs;

use crate::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use crate::error::{AfirmaError, Result, codes};
use crate::extra_params::ExtraParams;
use crate::http::{HttpClient, HttpClientError, HttpRequest, SslErrorHandling};
use crate::key::{KeyError, SigningKey};
use crate::signer::{CounterSignTarget, SignInfo, Signer, SignersTree};
use crate::triphase::{PROPERTY_NAME_PKCS1_SIGN, PROPERTY_NAME_PRESIGN, TriphaseData};

/// Sufijo de los ficheros firmados en PKCS#1.
pub const PKCS1_FILE_SUFFIX: &str = ".p1";
/// Parámetro con la URL del servidor trifásico.
pub const PROPERTY_NAME_SIGN_SERVER_URL: &str = "serverUrl";

/// Verifica una firma PKCS#1 (RSA) o ECDSA DER con la clave pública de un
/// certificado. `None` si la combinación de algoritmo y clave no está
/// soportada por el verificador (`ring`): SHA-224, DSA, curvas distintas de
/// P-256/P-384, SHA-1 con ECDSA o RSA de menos de 2048 bits con SHA-384.
pub fn verify_signature(cert_der: &[u8], algorithm: SignatureAlgorithm, data: &[u8], signature: &[u8]) -> Option<bool> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let spki = cert.public_key();
    let key_bytes = spki.subject_public_key.data.as_ref();
    let verifier: &dyn rs::VerificationAlgorithm = match algorithm.key {
        KeyAlgorithm::Rsa => match algorithm.digest {
            DigestAlgorithm::Sha1 => &rs::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            DigestAlgorithm::Sha256 => &rs::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            DigestAlgorithm::Sha384 => &rs::RSA_PKCS1_2048_8192_SHA384,
            DigestAlgorithm::Sha512 => &rs::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            DigestAlgorithm::Sha224 => return None,
        },
        KeyAlgorithm::Ec => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())?;
            match (curve.as_str(), algorithm.digest) {
                ("1.2.840.10045.3.1.7", DigestAlgorithm::Sha256) => &rs::ECDSA_P256_SHA256_ASN1,
                ("1.2.840.10045.3.1.7", DigestAlgorithm::Sha384) => &rs::ECDSA_P256_SHA384_ASN1,
                ("1.3.132.0.34", DigestAlgorithm::Sha256) => &rs::ECDSA_P384_SHA256_ASN1,
                ("1.3.132.0.34", DigestAlgorithm::Sha384) => &rs::ECDSA_P384_SHA384_ASN1,
                _ => return None,
            }
        }
        KeyAlgorithm::Dsa => return None,
    };
    Some(
        rs::UnparsedPublicKey::new(verifier, key_bytes)
            .verify(data, signature)
            .is_ok(),
    )
}

/// `AOPkcs1Signer.sign`: firma `data` con la clave (el algoritmo se compone
/// con el tipo de clave) y, si se indica la cadena, comprueba la firma con el
/// certificado `[0]` (ETSI TS 119 102-1).
///
/// Errores: algoritmo no soportado 600107; clave no válida 200110;
/// cancelación 500001; PIN incorrecto 501003; tarjeta bloqueada 511004;
/// otros fallos de firma 200111; firma que no corresponde al certificado
/// 200112.
pub fn pkcs1_sign(data: &[u8], algorithm: &str, key: &dyn SigningKey, cert_chain: &[Vec<u8>]) -> Result<Vec<u8>> {
    let key_type = key.key_algorithm();
    let alg_name =
        crate::algorithms::compose_signature_algorithm_name(Some(algorithm), Some(key_type.java_key_type()))?;
    let sig_alg = crate::algorithms::compose_signature_algorithm(algorithm, key_type).map_err(|_| {
        AfirmaError::unsupported_sign_algorithm(format!(
            "No se soporta el algoritmo de firma ({algorithm}): {alg_name}"
        ))
    })?;
    let signature = key.sign(data, sig_alg).map_err(|e| match e {
        KeyError::Cancelled => AfirmaError::cancelled_sm("Cancelacion del dialogo de JMulticard"),
        KeyError::WrongPin => AfirmaError::new(
            codes::INVALID_SMARTCARD_PIN,
            "La contrasena del almacen o certificado es incorrecta",
        ),
        KeyError::PinLocked => AfirmaError::new(codes::SMARTCARD_LOCKED, "El almacen de claves esta bloqueado"),
        KeyError::Unsupported(m) => AfirmaError::new(
            codes::INVALID_SIGNING_KEY,
            format!("Error al inicializar la firma con la clave privada para el algoritmo '{algorithm}': {m}"),
        ),
        other => AfirmaError::new(
            codes::SIGNING_PKCS1_ERROR,
            format!("Error durante el proceso de firma PKCS#1: {other}"),
        ),
    })?;
    match cert_chain.first() {
        Some(cert) => match verify_signature(cert, sig_alg, data, &signature) {
            Some(true) => {}
            Some(false) => {
                return Err(AfirmaError::new(
                    codes::INVALID_PKCS1_VALUE,
                    "El PKCS#1 de firma obtenido no se genero con el certificado indicado",
                ));
            }
            None => tracing::warn!("No se puede comprobar la integridad del PKCS#1 con el algoritmo {alg_name}"),
        },
        None => tracing::warn!("No se ha proporcionado el certificado para comprobar la integridad del PKCS#1"),
    }
    Ok(signature)
}

fn unsupported(msg: &str) -> AfirmaError {
    AfirmaError::unsupported(msg)
}

/// Firmador `NONE` (`AOPkcs1Signer`).
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs1Signer;

impl Signer for Pkcs1Signer {
    fn format_name(&self) -> &'static str {
        crate::constants::SIGN_FORMAT_PKCS1
    }

    fn sign(&self, data: &[u8], algorithm: &str, key: &dyn SigningKey, _extra: &ExtraParams) -> Result<Vec<u8>> {
        pkcs1_sign(data, algorithm, key, &key.certificate_chain())
    }

    fn cosign(&self, _: Option<&[u8]>, _: &[u8], _: &str, _: &dyn SigningKey, _: &ExtraParams) -> Result<Vec<u8>> {
        Err(unsupported("No se soporta la multifirma de las firmas NONE"))
    }

    fn countersign(
        &self,
        _: &[u8],
        _: &str,
        _: &CounterSignTarget,
        _: &dyn SigningKey,
        _: &ExtraParams,
    ) -> Result<Vec<u8>> {
        Err(unsupported("No se soporta la multifirma de las firmas NONE"))
    }

    fn signers_structure(&self, _: &[u8], _: &ExtraParams) -> Result<SignersTree> {
        Err(unsupported("No se puede obtener la estructura de firmantes en PKCS#1"))
    }

    fn is_sign(&self, _: &[u8], _: &ExtraParams) -> bool {
        false
    }

    fn is_valid_data_file(&self, data: &[u8]) -> bool {
        !data.is_empty()
    }

    /// `signature.p1` sin nombre; si termina en `.p1` (sin distinguir
    /// mayúsculas) se inserta el texto antes del sufijo.
    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        let in_text = in_text.unwrap_or("");
        match original {
            None => format!("signature{PKCS1_FILE_SUFFIX}"),
            Some(n) if n.to_ascii_lowercase().ends_with(PKCS1_FILE_SUFFIX) => {
                format!(
                    "{}{in_text}{PKCS1_FILE_SUFFIX}",
                    &n[..n.len() - PKCS1_FILE_SUFFIX.len()]
                )
            }
            Some(n) => format!("{n}{in_text}{PKCS1_FILE_SUFFIX}"),
        }
    }

    fn get_data(&self, _: &[u8], _: &ExtraParams) -> Result<Option<Vec<u8>>> {
        Err(unsupported("No se pueden obtener los datos firmados en PKCS#1"))
    }

    fn sign_info(&self, _: &[u8], _: &ExtraParams) -> Result<SignInfo> {
        Err(unsupported("No se puede obtener informacion de las firmas PKCS#1"))
    }
}

/// Firmador `NONEtri` (`AOPkcs1TriPhaseSigner`): la prefirma y la postfirma
/// las hace el servidor indicado en `serverUrl`.
#[derive(Clone)]
pub struct Pkcs1TriPhaseSigner {
    client: Option<Arc<dyn HttpClient>>,
}

impl std::fmt::Debug for Pkcs1TriPhaseSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs1TriPhaseSigner").finish_non_exhaustive()
    }
}

impl Default for Pkcs1TriPhaseSigner {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Pkcs1TriPhaseSigner {
    /// Firmador con el cliente HTTP indicado (`setHttpConnection`) o, si es
    /// `None`, el instalado en el proceso.
    pub fn new(client: Option<Arc<dyn HttpClient>>) -> Self {
        Pkcs1TriPhaseSigner { client }
    }

    fn client(&self) -> Arc<dyn HttpClient> {
        self.client.clone().unwrap_or_else(crate::http::installed_http_client)
    }

    /// `triPhaseOperation(format, cop, ...)` (protegido en Java, reutilizado
    /// por otros firmadores trifásicos simples).
    #[allow(clippy::too_many_arguments)]
    pub fn triphase_operation(
        &self,
        format: &str,
        crypto_operation: &str,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        cert_chain: &[Vec<u8>],
        extra_params: &ExtraParams,
    ) -> Result<Vec<u8>> {
        if cert_chain.is_empty() {
            return Err(AfirmaError::invalid_argument(
                "Es necesario proporcionar el certificado de firma",
            ));
        }
        let server = extra_params
            .get(PROPERTY_NAME_SIGN_SERVER_URL)
            .filter(|u| url::Url::parse(u).is_ok())
            .ok_or_else(|| {
                AfirmaError::invalid_argument(format!(
                    "No se ha proporcionado una URL valida para el servidor de firma: {}",
                    extra_params.get(PROPERTY_NAME_SIGN_SERVER_URL).unwrap_or("null")
                ))
            })?;
        let client = self.client();
        let document_id = crate::base64::encode_url_safe(data);
        let cert = crate::base64::encode_url_safe(&cert_chain[0]);
        let common = format!("cop={crypto_operation}&format={format}&algo={algorithm}&cert={cert}&doc={document_id}");
        let pre_url = format!("{server}?op=pre&{common}");
        let pre = client
            .read_url(&HttpRequest::post(pre_url).ssl_error_handling(SslErrorHandling::from_extra_params(extra_params)))
            .map_err(|e| presign_error(&e))?;
        let xml = crate::base64::decode_bytes(&pre, true).map_err(|e| {
            AfirmaError::new(
                codes::MALFORMED_PRESIGN_RESPONSE,
                format!("Error al analizar la prefirma enviada por el servidor: {e}"),
            )
        })?;
        let mut tri = TriphaseData::parse(&xml).map_err(|e| {
            AfirmaError::new(
                codes::MALFORMED_PRESIGN_RESPONSE,
                format!("Error al analizar la prefirma enviada por el servidor: {e}"),
            )
        })?;
        if tri.signs.is_empty() {
            return Err(AfirmaError::new(
                codes::PRESIGNS_NOT_FOUND,
                "No se han obtenido prefirmas del servicio de prefirma",
            ));
        }
        let presignature = tri.signs[0]
            .property(PROPERTY_NAME_PRESIGN)
            .ok_or_else(|| {
                AfirmaError::new(
                    codes::MALFORMED_PRESIGN_RESPONSE,
                    "Error al decodificar la prefirma de los datos",
                )
            })
            .and_then(|p| {
                crate::base64::decode(p).map_err(|_| {
                    AfirmaError::new(
                        codes::MALFORMED_PRESIGN_RESPONSE,
                        "Error al decodificar la prefirma de los datos",
                    )
                })
            })?;
        let pkcs1 = pkcs1_sign(&presignature, algorithm, key, cert_chain)?;
        tri.signs[0].add_property(PROPERTY_NAME_PKCS1_SIGN, crate::base64::encode(&pkcs1));
        let session = crate::base64::encode_url_safe(tri.to_xml_string().as_bytes());
        let post_url = format!("{server}?op=post&{common}&session={session}");
        let result = client
            .read_url(&HttpRequest::post(post_url))
            .map_err(|e| postsign_error(&e))?;
        let text = String::from_utf8_lossy(&result);
        let trimmed = text.trim_matches(|c: char| c <= ' ');
        if !trimmed.starts_with("OK") {
            return Err(AfirmaError::new(
                codes::POSTSIGN_ERROR,
                format!("La firma trifasica no ha finalizado correctamente: {trimmed}"),
            ));
        }
        let malformed = || {
            AfirmaError::new(
                codes::MALFORMED_POSTSIGN_RESPONSE,
                "El resultado devuelto por el servidor no es correcto",
            )
        };
        let encoded = trimmed.get("OK NEWID=".len()..).ok_or_else(malformed)?;
        crate::base64::decode_url_safe(encoded).map_err(|_| malformed())
    }
}

fn presign_error(e: &HttpClientError) -> AfirmaError {
    let mut err = AfirmaError::triphase_presign_connection(e);
    err.message = match e {
        HttpClientError::Http(_) => format!("El servicio de prefirma devolvio un error: {e}"),
        HttpClientError::Timeout { .. } => "La prefirma en servidor ha excedido el tiempo de espera".into(),
        _ => format!("Error en la llamada de prefirma al servidor: {e}"),
    };
    err
}

fn postsign_error(e: &HttpClientError) -> AfirmaError {
    let mut err = AfirmaError::triphase_postsign_connection(e);
    err.message = match e {
        HttpClientError::Http(_) => format!("El servicio de postfirma devolvio un error: {e}"),
        HttpClientError::Timeout { .. } => "La postfirma en servidor ha excedido el tiempo de espera".into(),
        _ => format!("Error en la llamada de postfirma al servidor: {e}"),
    };
    err
}

impl Signer for Pkcs1TriPhaseSigner {
    fn format_name(&self) -> &'static str {
        crate::constants::SIGN_FORMAT_PKCS1_TRI
    }

    fn sign(&self, data: &[u8], algorithm: &str, key: &dyn SigningKey, extra: &ExtraParams) -> Result<Vec<u8>> {
        self.triphase_operation(
            crate::constants::SIGN_FORMAT_PKCS1,
            "sign",
            data,
            algorithm,
            key,
            &key.certificate_chain(),
            extra,
        )
    }

    fn cosign(&self, _: Option<&[u8]>, _: &[u8], _: &str, _: &dyn SigningKey, _: &ExtraParams) -> Result<Vec<u8>> {
        Err(unsupported("No se soporta la multifirma de firmas NONE"))
    }

    fn countersign(
        &self,
        _: &[u8],
        _: &str,
        _: &CounterSignTarget,
        _: &dyn SigningKey,
        _: &ExtraParams,
    ) -> Result<Vec<u8>> {
        Err(unsupported("No se soporta la multifirma de firmas NONE"))
    }

    fn signers_structure(&self, _: &[u8], _: &ExtraParams) -> Result<SignersTree> {
        Err(unsupported("No se soporta en firma trifasica"))
    }

    fn is_sign(&self, _: &[u8], _: &ExtraParams) -> bool {
        false
    }

    fn is_valid_data_file(&self, _: &[u8]) -> bool {
        true
    }

    /// `nombre + texto + ".p1"` (sin comprobar el nombre nulo: `null.p1`).
    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        format!(
            "{}{}{PKCS1_FILE_SUFFIX}",
            original.unwrap_or("null"),
            in_text.unwrap_or("")
        )
    }

    fn get_data(&self, _: &[u8], _: &ExtraParams) -> Result<Option<Vec<u8>>> {
        Err(unsupported("No se soporta en firma trifasica"))
    }

    fn sign_info(&self, _: &[u8], _: &ExtraParams) -> Result<SignInfo> {
        Err(unsupported("No se soporta en firma trifasica"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Clave de pruebas RSA de `testdata/pki/firmante-rsa` firmando con ring.
    pub(crate) struct TestRsaKey {
        cert: Vec<u8>,
        key: rs::RsaKeyPair,
    }

    impl TestRsaKey {
        pub(crate) fn load() -> Self {
            let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/pki");
            let cert =
                crate::cert::decode_certificate(&std::fs::read(format!("{root}/firmante-rsa.crt")).unwrap()).unwrap();
            let pem = std::fs::read_to_string(format!("{root}/firmante-rsa.key")).unwrap();
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = crate::base64::decode(&b64).unwrap();
            let key = rs::RsaKeyPair::from_pkcs8(&der)
                .or_else(|_| rs::RsaKeyPair::from_der(&der))
                .unwrap();
            TestRsaKey { cert, key }
        }
    }

    impl SigningKey for TestRsaKey {
        fn certificate(&self) -> &[u8] {
            &self.cert
        }
        fn key_algorithm(&self) -> KeyAlgorithm {
            KeyAlgorithm::Rsa
        }
        fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> std::result::Result<Vec<u8>, KeyError> {
            let pad: &dyn rs::RsaEncoding = match algorithm.digest {
                DigestAlgorithm::Sha256 => &rs::RSA_PKCS1_SHA256,
                DigestAlgorithm::Sha384 => &rs::RSA_PKCS1_SHA384,
                DigestAlgorithm::Sha512 => &rs::RSA_PKCS1_SHA512,
                _ => return Err(KeyError::Unsupported(algorithm.java_name())),
            };
            let mut sig = vec![0u8; self.key.public().modulus_len()];
            self.key
                .sign(pad, &ring::rand::SystemRandom::new(), data, &mut sig)
                .map_err(|e| KeyError::Other(e.to_string()))?;
            Ok(sig)
        }
    }

    /// Clave que firma con otra clave distinta de la del certificado.
    struct WrongKey(TestRsaKey, Vec<u8>);
    impl SigningKey for WrongKey {
        fn certificate(&self) -> &[u8] {
            &self.1
        }
        fn key_algorithm(&self) -> KeyAlgorithm {
            KeyAlgorithm::Rsa
        }
        fn sign(&self, data: &[u8], a: SignatureAlgorithm) -> std::result::Result<Vec<u8>, KeyError> {
            let mut s = self.0.sign(data, a)?;
            s[10] ^= 0xff;
            Ok(s)
        }
    }

    #[test]
    fn pkcs1_signer() {
        let key = TestRsaKey::load();
        let sig = Pkcs1Signer
            .sign(b"datos", "SHA256withRSA", &key, &ExtraParams::new())
            .unwrap();
        assert_eq!(
            verify_signature(
                &key.cert,
                SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa),
                b"datos",
                &sig
            ),
            Some(true)
        );
        // Un nombre de huella o un algoritmo ECDSA se adaptan a la clave RSA.
        assert!(pkcs1_sign(b"x", "SHA-512", &key, &[]).is_ok());
        assert!(pkcs1_sign(b"x", "SHA384withECDSA", &key, std::slice::from_ref(&key.cert)).is_ok());
        let e = pkcs1_sign(b"x", "MD5withRSA", &key, &[]).unwrap_err();
        assert_eq!(e.code, Some(codes::UNSUPPORTED_SIGNATURE_ALGORITHM));
        let e = pkcs1_sign(b"x", "SHA1withRSA", &key, &[]).unwrap_err();
        assert_eq!(e.code, Some(codes::INVALID_SIGNING_KEY));
        let cert = key.cert.clone();
        let wrong = WrongKey(TestRsaKey::load(), cert.clone());
        let e = pkcs1_sign(b"x", "SHA256withRSA", &wrong, &[cert]).unwrap_err();
        assert_eq!(e.code, Some(codes::INVALID_PKCS1_VALUE));
        assert_eq!(Pkcs1Signer.signed_name(None, Some("_x")), "signature.p1");
        assert_eq!(Pkcs1Signer.signed_name(Some("a.P1"), Some("_x")), "a_x.p1");
        assert_eq!(Pkcs1Signer.signed_name(Some("a.txt"), None), "a.txt.p1");
        assert!(!Pkcs1Signer.is_sign(b"x", &ExtraParams::new()));
        assert!(!Pkcs1Signer.is_valid_data_file(b""));
        assert_eq!(
            Pkcs1Signer
                .cosign(None, b"", "", &key, &ExtraParams::new())
                .unwrap_err()
                .kind,
            crate::error::ErrorKind::Unsupported
        );
        assert_eq!(Pkcs1TriPhaseSigner::default().signed_name(None, None), "null.p1");
    }

    /// Servidor trifásico simulado.
    struct FakeTriServer {
        calls: Mutex<Vec<String>>,
        presign: Vec<u8>,
    }

    impl HttpClient for FakeTriServer {
        fn read_url(&self, r: &HttpRequest) -> std::result::Result<Vec<u8>, HttpClientError> {
            self.calls.lock().unwrap().push(r.url.clone());
            if r.url.contains("op=pre") {
                Ok(self.presign.clone())
            } else {
                Ok(format!("OK NEWID={}", crate::base64::encode_url_safe(b"firma final")).into_bytes())
            }
        }
    }

    #[test]
    fn pkcs1_triphase() {
        let key = TestRsaKey::load();
        let xml = format!(
            "<xml>\n <firmas>\n  <firma Id=\"1\">\n   <param n=\"PRE\">{}</param>\n  </firma>\n </firmas>\n</xml>",
            crate::base64::encode(b"prefirma")
        );
        let server = Arc::new(FakeTriServer {
            calls: Mutex::new(Vec::new()),
            presign: crate::base64::encode_url_safe(xml.as_bytes()).into_bytes(),
        });
        let signer = Pkcs1TriPhaseSigner::new(Some(server.clone()));
        let mut p = ExtraParams::new();
        p.set("serverUrl", "https://servidor/SignatureService");
        let r = signer.sign(b"documento", "SHA256withRSA", &key, &p).unwrap();
        assert_eq!(r, b"firma final");
        let calls = server.calls.lock().unwrap();
        assert!(
            calls[0]
                .starts_with("https://servidor/SignatureService?op=pre&cop=sign&format=NONE&algo=SHA256withRSA&cert=")
        );
        assert!(calls[0].ends_with(&format!("&doc={}", crate::base64::encode_url_safe(b"documento"))));
        let session = calls[1].split("&session=").nth(1).unwrap();
        let tri = TriphaseData::parse(&crate::base64::decode_url_safe(session).unwrap()).unwrap();
        let pk1 = crate::base64::decode(tri.signs[0].property("PK1").unwrap()).unwrap();
        assert_eq!(
            verify_signature(
                &key.cert,
                SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa),
                b"prefirma",
                &pk1
            ),
            Some(true)
        );
        // Sin URL de servidor.
        assert!(
            signer
                .sign(b"d", "SHA256withRSA", &key, &ExtraParams::new())
                .unwrap_err()
                .message
                .starts_with("No se ha proporcionado una URL valida")
        );
    }

    #[test]
    fn triphase_data_signer() {
        let key = TestRsaKey::load();
        let mut data = TriphaseData::new();
        let mut s1 = crate::triphase::TriSign::new(Some("1".into()), None);
        s1.add_property("PRE", crate::base64::encode(b"uno"));
        let mut s2 = crate::triphase::TriSign::new(Some("2".into()), None);
        s2.add_property("PRE", crate::base64::encode(b"dos"));
        s2.add_property("NEED_PRE", "TRUE");
        data.signs = vec![s1, s2];
        crate::triphase::do_sign(&mut data, "SHA512withRSA", &key, std::slice::from_ref(&key.cert)).unwrap();
        assert!(data.signs[0].property("PRE").is_none());
        assert!(data.signs[1].property("PRE").is_some());
        assert!(data.signs.iter().all(|s| s.property("PK1").is_some()));
        let mut empty = TriphaseData::new();
        assert_eq!(
            crate::triphase::do_sign(&mut empty, "SHA512withRSA", &key, &[])
                .unwrap_err()
                .code,
            Some(codes::PRESIGNS_NOT_FOUND)
        );
        let mut no_pre = TriphaseData {
            format: None,
            signs: vec![crate::triphase::TriSign::new(None, None)],
        };
        assert_eq!(
            crate::triphase::do_sign(&mut no_pre, "SHA512withRSA", &key, &[])
                .unwrap_err()
                .message,
            "El servidor no ha devuelto la prefirma numero 0"
        );
    }
}
