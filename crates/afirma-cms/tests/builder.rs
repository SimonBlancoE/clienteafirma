//! API para PAdES/trifásica: firma de una huella externa y división
//! prefirma/postfirma.

mod common;

use afirma_cms::builder::{SignatureAlgorithmOid, SignedDataBuilder};
use afirma_cms::cades::{self, CadesParameters};
use afirma_cms::cms::SignedData;
use afirma_cms::{inspect, oids, pkcs1, validation};
use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::validity::Validity;
use afirma_core::{ExtraParams, SigningKey};
use common::*;

#[test]
fn detached_signature_for_external_digest() {
    let k = key("firmante-rsa");
    let data = read("cades/data/hola.txt");
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    let mut extra = ExtraParams::new();
    extra.set("includeSigningTimeAttribute", "false");
    extra.set("signerClaimedRoles", "Alcalde");
    let mut b = SignedDataBuilder::for_digest(
        &DigestAlgorithm::Sha256.digest(&data),
        alg,
        k.certificate_chain(),
        &extra,
        cades::now(),
    )
    .unwrap();
    // PAdES ETSI.CAdES.detached: sin contentHints.
    b.params.content_type_oid = None;
    b.params.content_description = None;
    b.signature_algorithm_oid = SignatureAlgorithmOid::Full;
    // Firma en dos pasos (trifásica).
    let tbs = b.signed_attributes().unwrap();
    let sig = pkcs1::sign(&k, &tbs, alg, Some(k.certificate())).unwrap();
    let cms = b.assemble(&tbs, &sig).unwrap();
    let d = &inspect::signers(&cms).unwrap()[0];
    assert!(d.signing_time.is_none());
    assert!(!d.signed_attribute_oids.contains(&oids::CONTENT_HINT.to_string()));
    assert!(d.signed_attribute_oids.contains(&oids::SIGNER_ATTR.to_string()));
    assert_eq!(d.signature_algorithm_oid, "1.2.840.113549.1.1.11");
    assert_eq!(d.profile, "CAdES-BES");
    assert_eq!(validation::validate(&cms, Some(&data), true)[0].validity, Validity::Ok);
    if let Some((ok, msg)) = openssl_verify("builder", &cms, Some(&data)) {
        assert!(ok, "{msg}");
    }
    // Firma directa con la misma configuración.
    let direct = b.sign(&k).unwrap();
    assert_eq!(SignedData::parse(&direct).unwrap().signer_infos.len(), 1);
}

#[test]
fn pades_cms_attributes() {
    // Especificación 04 §6.3: por defecto {contentType, messageDigest, signingCertificateV2}.
    let k = key("firmante-rsa");
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    let digest = DigestAlgorithm::Sha256.digest(b"rangos del PDF");
    let mut extra = ExtraParams::new();
    extra.set("signatureProductionCity", "Madrid");
    let b = SignedDataBuilder::for_pades(&digest, alg, k.certificate_chain(), &extra).unwrap();
    let cms = b.sign(&k).unwrap();
    let d = &inspect::signers(&cms).unwrap()[0];
    let mut oids_found = d.signed_attribute_oids.clone();
    oids_found.sort();
    let mut expected = vec![oids::CONTENT_TYPE, oids::MESSAGE_DIGEST, oids::SIGNING_CERTIFICATE_V2];
    expected.sort();
    assert_eq!(oids_found, expected);
    assert_eq!(d.signature_algorithm_oid, oids::RSA_ENCRYPTION);
    assert_eq!(d.message_digest.as_deref(), Some(digest.as_slice()));
    let sd = SignedData::parse(&cms).unwrap();
    assert!(sd.econtent.is_none());
    assert_eq!(sd.certificates_der().len(), 2);
    let mut b2 = b.clone();
    b2.include_content_type = false;
    let tbs = b2.signed_attributes().unwrap();
    assert!(!tbs.windows(11).any(|w| w == afirma_cms::asn1::der::oid_str(oids::CONTENT_TYPE).as_slice()));
}

#[test]
fn pre_and_post_sign_split_matches_one_step_sign() {
    let k = key("firmante-rsa");
    let now = cades::now();
    let mut extra = ExtraParams::new();
    extra.set("mode", "implicit");
    let one_step = cades::sign_at(b"Hola mundo", "SHA256withRSA", &k, &extra, now).unwrap();
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    let cfg = CadesParameters::load(Some(b"Hola mundo"), None, "SHA256withRSA", &extra, now).unwrap();
    let chain = k.certificate_chain();
    let pre = cades::pre_sign(&chain[0], &cfg).unwrap();
    let sig = k.sign(&pre, alg).unwrap();
    let two_steps = cades::post_sign(alg, cfg.content_data.as_deref(), &chain, &sig, &pre).unwrap();
    // RSA PKCS#1 v1.5 es determinista: el resultado es idéntico byte a byte.
    assert_eq!(one_step, two_steps);
}

/// El CMS de PAdES de Java (extraído de `/Contents` de un PDF firmado por la
/// AutoFirma Java) es idéntico byte a byte al de `SignedDataBuilder::for_pades`
/// con la misma huella (RSA PKCS#1 v1.5 es determinista y PAdES no lleva
/// `signingTime`).
#[test]
fn pades_cms_is_byte_identical_to_java() {
    let k = key("firmante-rsa");
    for (file, alg, params) in [
        ("cades/pades_cms_sha256.java.p7s", DigestAlgorithm::Sha256, vec![]),
        (
            "cades/pades_cms_epes.java.p7s",
            DigestAlgorithm::Sha512,
            vec![
                ("policyIdentifier", "urn:oid:2.16.724.1.3.1.1.2.1.9"),
                ("policyIdentifierHash", "G7roucf600+f03r/o0bAOQ6WAs0="),
                ("policyIdentifierHashAlgorithm", "SHA1"),
                ("signerClaimedRoles", "Alcalde"),
                ("includeOnlySignningCertificate", "true"),
            ],
        ),
    ] {
        let java = read(file);
        let md = SignedData::parse(&java).unwrap().signer_infos[0].message_digest().unwrap();
        let extra: ExtraParams = params.into_iter().collect();
        let b = SignedDataBuilder::for_pades(
            &md,
            SignatureAlgorithm::new(alg, KeyAlgorithm::Rsa),
            k.certificate_chain(),
            &extra,
        )
        .unwrap();
        assert_eq!(hex::encode(b.sign(&k).unwrap()), hex::encode(&java), "{file}");
    }
}
