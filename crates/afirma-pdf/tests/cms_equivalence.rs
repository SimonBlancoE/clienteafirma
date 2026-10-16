//! Equivalencia entre los atributos/CMS de PAdES de este crate y los de
//! `afirma_cms::SignedDataBuilder::for_pades`.

mod common;

use afirma_core::algorithms::compose_signature_algorithm;
use afirma_core::{KeyAlgorithm, SigningKey};
use afirma_pdf::cms;
use common::{TestKey, params};

#[test]
fn same_signed_attributes_and_cms() {
    type Case<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>);
    let cases: Vec<Case> = vec![
        ("firmante-rsa", "SHA256withRSA", vec![]),
        ("firmante-rsa", "SHA512withRSA", vec![]),
        ("firmante-rsa", "SHA1withRSA", vec![]),
        (
            "firmante-rsa",
            "SHA1withRSA",
            vec![("signingCertificateV2", "true")],
        ),
        (
            "firmante-rsa",
            "SHA256withRSA",
            vec![("doNotIncludePolicyOnSigningCertificate", "true")],
        ),
        (
            "firmante-rsa",
            "SHA256withRSA",
            vec![
                ("policyIdentifier", "urn:oid:2.16.724.1.3.1.1.2.1.9"),
                ("policyIdentifierHash", "G7roucf600+f03r/o0bAOQ6WAs0="),
                (
                    "policyIdentifierHashAlgorithm",
                    "http://www.w3.org/2000/09/xmldsig#sha1",
                ),
                (
                    "policyQualifier",
                    "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
                ),
                ("commitmentTypeIndications", "1"),
                ("commitmentTypeIndication0Identifier", "1"),
                ("commitmentTypeIndication1Identifier", "5"),
                (
                    "commitmentTypeIndication1CommitmentTypeQualifiers",
                    "1.2.3|1.2.4",
                ),
            ],
        ),
        (
            "firmante-rsa",
            "SHA256withRSA",
            vec![("signerClaimedRoles", "Jefe|Firmante")],
        ),
        (
            "firmante-rsa",
            "SHA256withRSA",
            vec![("signerClaimedRoles", "Jefe"), ("profile", "baseline")],
        ),
        (
            "firmante-rsa",
            "SHA256withRSA",
            vec![("includeMimeTypeAttribute", "true")],
        ),
        ("firmante-ec", "SHA384withECDSA", vec![]),
    ];
    let digest = [7u8; 64];
    for (key, alg, extra) in cases {
        let k = TestKey::load(key);
        let ka = if key.ends_with("ec") {
            KeyAlgorithm::Ec
        } else {
            KeyAlgorithm::Rsa
        };
        let a = compose_signature_algorithm(alg, ka).unwrap();
        let mut xp = params(&extra);
        afirma_pdf::pades::params::check_params(alg, &mut xp).unwrap();
        let md = &digest[..a.digest.output_len()];
        let cfg = afirma_pdf::pades::signed_attrs_config(a, &xp).unwrap();
        let chain = k.certificate_chain();
        let mine = cms::signed_attributes(md, &chain[0], &cfg).unwrap();
        let b = afirma_cms::SignedDataBuilder::for_pades(md, a, chain.clone(), &xp).unwrap();
        let theirs = b.signed_attributes().unwrap();
        assert_eq!(
            hex::encode(&mine),
            hex::encode(&theirs),
            "{key} {alg} {extra:?}"
        );
        let sig = vec![1u8; 256];
        let c1 = cms::signed_data(&mine, &sig, &chain, a, None).unwrap();
        let c2 = b.assemble(&theirs, &sig).unwrap();
        assert_eq!(
            hex::encode(&c1),
            hex::encode(&c2),
            "CMS {key} {alg} {extra:?}"
        );
    }
}
