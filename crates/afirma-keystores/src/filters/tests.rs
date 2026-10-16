//! Pruebas de los filtros de certificados con la PKI de pruebas
//! (`testdata/pki`), los certificados sintéticos de
//! `testdata/keystores/filters` (generados con
//! `tools/oracle/filters_gen_certs.py`) y certificados generados con `rcgen`.

use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};

use super::*;
use crate::store::EntryCapabilities;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn load(rel: &str) -> Vec<u8> {
    afirma_core::cert::decode_certificate(&std::fs::read(testdata().join(rel)).unwrap()).unwrap()
}

/// Entrada con alias = nombre del fichero sin extensión. Los certificados del
/// DNIe llevan la CA intermedia en la cadena.
fn entry(rel: &str) -> CertEntry {
    let der = load(rel);
    let alias = Path::new(rel).file_stem().unwrap().to_str().unwrap().to_string();
    let mut chain = vec![der.clone()];
    if alias.starts_with("dnie-") && alias != "dnie-ca" {
        chain.push(load("keystores/filters/dnie-ca.der"));
    }
    CertEntry::new(
        alias,
        der,
        chain,
        EntryCapabilities {
            has_private_key: true,
            ..Default::default()
        },
        "pruebas",
    )
}

const PKI: [&str; 6] = ["firmante-rsa", "firmante-ec", "autenticacion", "caducado", "ca", "tsa"];
const SYNTH: [&str; 25] = [
    "accv-auth",
    "accv-firma",
    "cnp",
    "cn-repetido",
    "dnie-auth",
    "dnie-auth-otro",
    "dnie-ca",
    "dnie-firma",
    "escapes",
    "fnmt-otro",
    "futuro",
    "ku-agreement",
    "ku-cifrado",
    "ku-todos",
    "multivalor",
    "politicas",
    "pseudonimo",
    "pseudonimo-gemelo",
    "qc-sin-sscd",
    "representante",
    "sin-keyusage",
    "solo-o",
    "solo-ou",
    "sujeto-vacio",
    "tipos-cadena",
];

/// Todas las entradas de prueba.
fn all() -> Vec<CertEntry> {
    PKI.iter()
        .map(|n| entry(&format!("pki/{n}.crt")))
        .chain(SYNTH.iter().map(|n| entry(&format!("keystores/filters/{n}.der"))))
        .collect()
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 16, 12, 0, 0).unwrap()
}

fn manager(props: &[(&str, &str)]) -> Result<CertFilterManager, FilterError> {
    CertFilterManager::from_lookup(|k| props.iter().find(|(pk, _)| *pk == k).map(|(_, v)| v.to_string()))
}

/// Alias aceptados (ordenados) por la expresión `filters=<expr>`.
fn accepted(expr: &str) -> Vec<String> {
    accepted_props(&[("filters", expr)])
}

fn accepted_props(props: &[(&str, &str)]) -> Vec<String> {
    let m = manager(props).unwrap();
    let mut v: Vec<String> = m.apply(&all(), now()).into_iter().map(|e| e.alias).collect();
    v.sort();
    v
}

fn names(list: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = list.iter().map(|s| s.to_string()).collect();
    v.sort();
    v
}

fn everything() -> Vec<String> {
    let mut v: Vec<String> = PKI.iter().chain(SYNTH.iter()).map(|s| s.to_string()).collect();
    v.sort();
    v
}

fn everything_but(excluded: &[&str]) -> Vec<String> {
    everything()
        .into_iter()
        .filter(|a| !excluded.contains(&a.as_str()))
        .collect()
}

fn serial_of(alias: &str) -> String {
    let e = all().into_iter().find(|e| e.alias == alias).unwrap();
    use x509_parser::prelude::*;
    let (_, c) = X509Certificate::from_der(&e.certificate).unwrap();
    hex::encode_upper(c.raw_serial())
}

#[test]
fn configuration_precedence_and_defaults() {
    // Sin claves: filtro por defecto de caducados.
    let m = manager(&[]).unwrap();
    assert_eq!(m.filters(), &[CertFilter::Expired { show_expired: false }]);
    assert!(!m.is_mandatory_certificate());
    assert!(m.allow_external_stores());
    assert_eq!(accepted_props(&[]), everything_but(&["caducado", "futuro"]));
    // `filter` tiene precedencia sobre `filters` y `filters.N`.
    let m = manager(&[("filter", "dnie:"), ("filters", "sscd:"), ("filters.1", "authcert:")]).unwrap();
    assert_eq!(m.filters(), &[CertFilter::SignatureDnie]);
    let m = manager(&[("filters", "sscd:"), ("filters.1", "authcert:")]).unwrap();
    assert_eq!(m.filters(), &[CertFilter::Sscd]);
    // `filters.N` contiguos: se detiene en el primer hueco.
    let m = manager(&[
        ("filters.1", "dnie:"),
        ("filters.2", "sscd:"),
        ("filters.4", "authcert:"),
    ])
    .unwrap();
    assert_eq!(m.filters(), &[CertFilter::SignatureDnie, CertFilter::Sscd]);
    // `filters.2` sin `filters.1`: no hay filtros → por defecto.
    let m = manager(&[("filters.2", "sscd:")]).unwrap();
    assert_eq!(m.filters(), &[CertFilter::Expired { show_expired: false }]);
    // Con cualquier clave no se añade el filtro de caducados.
    assert!(accepted("keyusage.nonrepudiation:true").contains(&"caducado".to_string()));
    // Clave presente pero vacía o desconocida: expresión vacía, acepta todo.
    assert_eq!(accepted(""), everything());
    assert_eq!(accepted("desconocido:x;otro"), everything());
    let m = manager(&[("filters", "noexiste")]).unwrap();
    assert_eq!(m.filters(), &[CertFilter::Multiple(vec![])]);
}

#[test]
fn mandatory_and_external_stores() {
    assert!(manager(&[("headless", "TRUE")]).unwrap().is_mandatory_certificate());
    assert!(!manager(&[("headless", "si")]).unwrap().is_mandatory_certificate());
    assert!(
        manager(&[("mandatoryCertSelection", "False")])
            .unwrap()
            .is_mandatory_certificate()
    );
    assert!(
        !manager(&[("mandatoryCertSelection", "true")])
            .unwrap()
            .is_mandatory_certificate()
    );
    let m = manager(&[("filters", "DisableOpeningExternalStores;dnie:")]).unwrap();
    assert!(!m.allow_external_stores());
    assert_eq!(m.filters(), &[CertFilter::SignatureDnie]);
    // Solo `disableopeningexternalstores`: expresión vacía (acepta todo),
    // sin filtro por defecto.
    let m = manager(&[("filters", "disableopeningexternalstores")]).unwrap();
    assert_eq!(m.filters(), &[CertFilter::Multiple(vec![])]);
    // En `filters.2` también cuenta.
    let m = manager(&[
        ("filters.1", "dnie:"),
        ("filters.2", "sscd:;disableopeningexternalstores"),
    ])
    .unwrap();
    assert!(!m.allow_external_stores());
}

#[test]
fn construction_errors() {
    assert_eq!(
        manager(&[("filters", "subject.rfc2254:")]),
        Err(FilterError::EmptyCriteria)
    );
    assert_eq!(
        manager(&[("filters", "issuer.rfc2254:")]),
        Err(FilterError::EmptyCriteria)
    );
    assert_eq!(
        manager(&[("filters", "dnie:;issuer.rfc2254.recurse:")]),
        Err(FilterError::EmptyCriteria)
    );
    assert_eq!(manager(&[("filters", "policyid:,")]), Err(FilterError::EmptyPolicyList));
    // `policyid:` sin valor se ignora.
    assert_eq!(accepted("policyid:"), everything());
    // Un filtro RFC 2254 con espacios no es vacío.
    assert!(manager(&[("filters", "subject.rfc2254: ")]).is_ok());
}

#[test]
fn and_items_are_sorted() {
    let m = manager(&[("filters", "nonexpired:;keyusage.nonrepudiation:true")]).unwrap();
    assert_eq!(
        m.filters(),
        &[CertFilter::Multiple(vec![
            CertFilter::KeyUsage([None, Some(true), None, None, None, None, None, None, None]),
            CertFilter::Expired { show_expired: false },
        ])]
    );
    // Los keyusage consecutivos forman un patrón (y cada uno genera el suyo
    // desde su posición, como Java).
    let m = manager(&[(
        "filters",
        "keyusage.nonrepudiation:true;keyusage.digitalsignature:YES;keyusage.keyagreement:null",
    )])
    .unwrap();
    assert_eq!(
        m.filters(),
        &[CertFilter::Multiple(vec![
            CertFilter::KeyUsage([Some(false), Some(true), None, None, None, None, None, None, None]),
            CertFilter::KeyUsage([None, Some(true), None, None, None, None, None, None, None]),
            CertFilter::KeyUsage([None, Some(true), None, None, None, None, None, None, None]),
        ])]
    );
    // `KeyUsage.` en mayúsculas se reconoce pero no encadena con el
    // siguiente (comparación sensible a mayúsculas).
    let m = manager(&[("filters", "KeyUsage.digitalsignature:true;KeyUsage.nonrepudiation:true")]).unwrap();
    assert_eq!(
        m.filters(),
        &[CertFilter::Multiple(vec![
            CertFilter::KeyUsage([Some(true), None, None, None, None, None, None, None, None]),
            CertFilter::KeyUsage([None, Some(true), None, None, None, None, None, None, None]),
        ])]
    );
}

#[test]
fn dnie_filters() {
    assert_eq!(accepted("dnie:"), names(&["dnie-firma"]));
    assert_eq!(accepted("DNIE:cualquiercosa"), names(&["dnie-firma"]));
    assert_eq!(
        accepted("signingcert:"),
        everything_but(&["dnie-auth", "dnie-auth-otro"])
    );
    assert_eq!(accepted("authcert:"), everything_but(&["dnie-firma"]));
    // Sin dos puntos no se reconoce.
    assert_eq!(accepted("signingcert"), everything());
}

#[test]
fn ssl_filter() {
    let auth = serial_of("dnie-auth");
    assert_eq!(auth, "0080AB12");
    // El de autenticación del DNIe se sustituye por su pareja de firma.
    assert_eq!(accepted(&format!("ssl:{auth}")), names(&["dnie-firma"]));
    assert_eq!(accepted("ssl:80ab12"), names(&["dnie-firma"]));
    assert_eq!(accepted("ssl: # 00 80 AB 12 "), names(&["dnie-firma"]));
    // Sin pareja: nada.
    assert_eq!(
        accepted(&format!("ssl:{}", serial_of("dnie-auth-otro"))),
        Vec::<String>::new()
    );
    // Los demás se devuelven tal cual.
    assert_eq!(
        accepted(&format!("ssl:{}", serial_of("firmante-rsa"))),
        names(&["firmante-rsa"])
    );
    assert_eq!(
        accepted(&format!("ssl:{}", serial_of("autenticacion"))),
        names(&["autenticacion"])
    );
    assert_eq!(accepted("ssl:1122"), names(&["dnie-firma"]));
    assert_eq!(accepted("ssl:FFFF"), Vec::<String>::new());
}

#[test]
fn qualified_filter() {
    assert_eq!(
        accepted(&format!("qualified:{}", serial_of("dnie-auth"))),
        names(&["dnie-firma"])
    );
    assert_eq!(
        accepted(&format!("qualified:{}", serial_of("dnie-firma"))),
        names(&["dnie-firma"])
    );
    // Autenticación del DNIe sin pareja: nada.
    assert_eq!(
        accepted(&format!("qualified:{}", serial_of("dnie-auth-otro"))),
        Vec::<String>::new()
    );
    // Patrón de ACCV: el de firma solo tiene digitalSignature.
    assert_eq!(
        accepted(&format!("qualified:{}", serial_of("accv-auth"))),
        names(&["accv-firma"])
    );
    assert_eq!(
        accepted(&format!("qualified:{}", serial_of("accv-firma"))),
        names(&["accv-firma"])
    );
    // PKI de pruebas: la pareja de firma del de autenticación.
    assert_eq!(
        accepted(&format!("qualified:{}", serial_of("autenticacion"))),
        names(&["firmante-rsa"])
    );
    // Sin pareja y sin ser de autenticación del DNIe: el propio. (Con todos
    // los certificados de prueba hay varias "parejas" posibles —mismo emisor,
    // sin serialNumber y misma caducidad— y Java devuelve la primera en el
    // orden de su Hashtable; aquí, la primera en el orden recibido.)
    let set: Vec<CertEntry> = all()
        .into_iter()
        .filter(|e| ["ku-cifrado", "sin-keyusage", "firmante-rsa", "dnie-firma"].contains(&e.alias.as_str()))
        .collect();
    let pick = |expr: &str| -> Vec<String> {
        manager(&[("filters", expr)])
            .unwrap()
            .apply(&set, now())
            .into_iter()
            .map(|e| e.alias)
            .collect()
    };
    assert_eq!(
        pick(&format!("qualified:{}", serial_of("ku-cifrado"))),
        names(&["ku-cifrado"])
    );
    // Sin keyUsage nunca es "de firma"; sin pareja → el propio.
    assert_eq!(
        pick(&format!("qualified:{}", serial_of("sin-keyusage"))),
        names(&["sin-keyusage"])
    );
    let v = accepted(&format!("qualified:{}", serial_of("ku-cifrado")));
    assert_eq!(v.len(), 1);
    assert_ne!(v[0], "ku-cifrado");
}

#[test]
fn expiry_filter() {
    assert_eq!(accepted("nonexpired:"), everything_but(&["caducado", "futuro"]));
    assert_eq!(accepted("NONEXPIRED:"), everything_but(&["caducado", "futuro"]));
    assert_eq!(accepted("nonexpired:true"), everything_but(&["caducado", "futuro"]));
    assert_eq!(accepted("nonexpired:false"), everything());
    assert_eq!(accepted("nonexpired:quizas"), everything());
}

#[test]
fn sscd_and_policies() {
    assert_eq!(accepted("sscd:"), names(&["dnie-firma"]));
    assert_eq!(
        accepted("policyid:2.16.724.1.3.5.7.1,1.3.6.1.4.1.5734.3.10.1"),
        names(&["politicas"])
    );
    // Política de más: rechazado.
    assert_eq!(accepted("policyid:2.16.724.1.3.5.7.1"), Vec::<String>::new());
    assert_eq!(
        accepted("policyid:2.16.724.1.3.5.7.1,1.3.6.1.4.1.5734.3.10"),
        names(&["caducado", "firmante-ec", "firmante-rsa"])
    );
    // Sin recortar: el espacio cuenta.
    assert_eq!(
        accepted("policyid:2.16.724.1.3.5.7.1, 1.3.6.1.4.1.5734.3.10.1"),
        Vec::<String>::new()
    );
    assert_eq!(
        accepted("policyid:2.16.724.1.2.2.2.3,2.16.724.1.2.2.2.4"),
        names(&["dnie-auth", "dnie-firma"])
    );
}

#[test]
fn keyusage_filter() {
    let nr = accepted("keyusage.nonrepudiation:true");
    assert!(nr.contains(&"dnie-firma".to_string()) && nr.contains(&"firmante-rsa".to_string()));
    assert!(!nr.contains(&"sin-keyusage".to_string()) && !nr.contains(&"autenticacion".to_string()));
    // Patrón todo nulo: cualquiera con keyUsage, nunca sin la extensión.
    assert_eq!(
        accepted("keyusage.digitalsignature:null"),
        everything_but(&["sin-keyusage"])
    );
    assert_eq!(
        accepted("keyusage.digitalsignature:true;keyusage.nonrepudiation:false"),
        names(&[
            "accv-auth",
            "accv-firma",
            "autenticacion",
            "dnie-auth",
            "dnie-auth-otro"
        ])
    );
    assert_eq!(
        accepted("keyusage.keyagreement:true;keyusage.encipheronly:true"),
        names(&["ku-agreement"])
    );
    assert_eq!(
        accepted("keyusage.dataencipherment:true"),
        names(&["ku-cifrado", "ku-todos"])
    );
    assert_eq!(
        accepted("keyusage.keycertsign:true;keyusage.crlsign:true"),
        names(&["ca", "dnie-ca"])
    );
    // "yes" equivale a false.
    assert_eq!(
        accepted("keyusage.keycertsign:yes"),
        everything_but(&["ca", "dnie-ca", "sin-keyusage"])
    );
}

#[test]
fn rfc2254_filters() {
    assert_eq!(accepted("subject.rfc2254:(cn=PRUEBA*)"), names(&["firmante-ec"]));
    assert_eq!(accepted("subject.rfc2254:cn=prueba maria*"), names(&["firmante-ec"]));
    assert_eq!(
        accepted("subject.rfc2254:(serialnumber=IDCES-*)"),
        names(&["autenticacion", "firmante-ec", "firmante-rsa", "representante"])
    );
    assert_eq!(accepted("subject.rfc2254:(OID.2.5.4.65=*)"), names(&["pseudonimo"]));
    assert_eq!(
        accepted("issuer.rfc2254:(|(o=FNMT-RCM)(o=DIRECCION GENERAL DE LA POLICIA))"),
        names(&[
            "cnp",
            "dnie-auth",
            "dnie-auth-otro",
            "dnie-ca",
            "dnie-firma",
            "fnmt-otro",
            "pseudonimo",
            "pseudonimo-gemelo",
            "representante"
        ])
    );
    // RDN repetido: cuenta el situado más a la izquierda en toString().
    assert_eq!(accepted("subject.rfc2254:(cn=CN Segundo)"), names(&["cn-repetido"]));
    assert_eq!(accepted("subject.rfc2254:(cn=CN Primero)"), Vec::<String>::new());
    // RDN multivaluado: solo el tipo menor (CN) y GIVENNAME.
    assert_eq!(
        accepted("subject.rfc2254:(&(cn=Nombre A)(givenname=MARIA))"),
        names(&["multivalor"])
    );
    assert_eq!(accepted("subject.rfc2254:(ou=Unidad B)"), Vec::<String>::new());
    // Valores no textuales: solo presencia.
    assert_eq!(accepted("subject.rfc2254:(st=*)"), names(&["escapes", "tipos-cadena"]));
    assert_eq!(accepted("subject.rfc2254:(st=Visible)"), Vec::<String>::new());
    assert_eq!(
        accepted("subject.rfc2254:(street=Ya entre comillas)"),
        names(&["escapes"])
    );
    // Falla en abierto, salvo nombres vacíos.
    assert_eq!(accepted("subject.rfc2254:(cn:=x)"), everything_but(&["sujeto-vacio"]));
    assert_eq!(
        accepted("subject.rfc2254:(cn=*)"),
        everything_but(&["sujeto-vacio", "solo-o", "solo-ou"])
    );
    // Recursivo: algún certificado de la cadena (incluido el propio) con
    // titular que cumpla el filtro.
    assert_eq!(
        accepted("issuer.rfc2254.recurse:(cn=AC DNIE 004)"),
        names(&["dnie-auth", "dnie-auth-otro", "dnie-ca", "dnie-firma"])
    );
    assert_eq!(
        accepted("issuer.rfc2254.recurse:(cn=AC RAIZ DNIE 2)"),
        Vec::<String>::new()
    );
    assert_eq!(
        accepted("issuer.rfc2254.recurse:(cn=PRUEBA MARIA*)"),
        names(&["firmante-ec"])
    );
}

#[test]
fn text_and_thumbprint_filters() {
    assert_eq!(
        accepted("subject.contains:12345678z"),
        names(&["dnie-auth", "dnie-firma"])
    );
    assert_eq!(
        accepted("issuer.contains:O=FNMT"),
        names(&["fnmt-otro", "pseudonimo", "pseudonimo-gemelo", "representante"])
    );
    assert_eq!(accepted("subject.contains:"), everything());
    assert_eq!(
        accepted("Subject.Contains:OID.2.5.4.97=VATES"),
        names(&["representante"])
    );
    let rsa = entry("pki/firmante-rsa.crt");
    let sha256 = rsa.sha256_hex();
    let spaced: String = sha256
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        accepted(&format!("thumbprint:SHA-256:{spaced}")),
        names(&["firmante-rsa"])
    );
    assert_eq!(
        accepted(&format!("thumbprint:sha256:{}", sha256.to_uppercase())),
        names(&["firmante-rsa"])
    );
    assert_eq!(
        accepted(&format!("thumbprint:SHA1:{}", rsa.sha1_upper)),
        names(&["firmante-rsa"])
    );
    assert_eq!(
        accepted(&format!("thumbprint:SHA:{}", rsa.sha1_upper.to_lowercase())),
        names(&["firmante-rsa"])
    );
    let md5 = {
        use md5::Digest;
        hex::encode(md5::Md5::digest(&rsa.certificate))
    };
    assert_eq!(accepted(&format!("thumbprint:MD5:{md5}")), names(&["firmante-rsa"]));
    assert_eq!(accepted(&format!("thumbprint:SHA3-256:{md5}")), Vec::<String>::new());
    // Parámetros mal formados: se ignora el elemento.
    assert_eq!(accepted("thumbprint:SHA1"), everything());
    assert_eq!(accepted("thumbprint:SHA1:"), everything());
    assert_eq!(accepted("thumbprint:a:b:c"), everything());
}

#[test]
fn pseudonym_filter() {
    assert_eq!(accepted("pseudonym:only"), names(&["pseudonimo"]));
    assert_eq!(accepted("pseudonym:ONLY"), names(&["pseudonimo"]));
    // Por defecto (andothers): se oculta el gemelo no seudónimo.
    assert_eq!(accepted("pseudonym:"), everything_but(&["pseudonimo-gemelo"]));
    assert_eq!(accepted("pseudonym:andothers"), everything_but(&["pseudonimo-gemelo"]));
    assert_eq!(accepted("pseudonym:otracosa"), everything_but(&["pseudonimo-gemelo"]));
    // Sin seudónimos en el conjunto: todos.
    let m = manager(&[("filters", "pseudonym:")]).unwrap();
    let set: Vec<CertEntry> = all().into_iter().filter(|e| e.alias != "pseudonimo").collect();
    assert_eq!(m.apply(&set, now()).len(), set.len());
    let m = manager(&[("filters", "pseudonym:only")]).unwrap();
    assert!(m.apply(&set, now()).is_empty());
}

#[test]
fn encoded_cert_filter() {
    let ec = entry("pki/firmante-ec.crt");
    let b64 = afirma_core::base64_encode(&ec.certificate);
    assert_eq!(accepted(&format!("encodedcert:{b64}")), names(&["firmante-ec"]));
    assert_eq!(accepted("encodedcert:"), Vec::<String>::new());
}

#[test]
fn or_semantics_on_remaining_aliases() {
    // Unión de expresiones.
    let v = accepted_props(&[
        ("filters.1", "dnie:"),
        ("filters.2", "issuer.contains:O=FNMT-RCM;nonexpired:"),
    ]);
    assert_eq!(
        v,
        names(&[
            "dnie-firma",
            "fnmt-otro",
            "pseudonimo",
            "pseudonimo-gemelo",
            "representante"
        ])
    );
    // La segunda expresión solo ve lo que no aceptó la primera: el filtro
    // ssl no encuentra la pareja de firma, que ya fue aceptada.
    let v = accepted_props(&[
        ("filters.1", "keyusage.nonrepudiation:true;subject.contains:12345678Z"),
        ("filters.2", "ssl:80AB12"),
    ]);
    assert_eq!(v, names(&["dnie-firma"]));
    let v = accepted_props(&[
        ("filters.1", "subject.contains:OTRA PERSONA"),
        ("filters.2", "ssl:80AB12"),
    ]);
    assert_eq!(v, names(&["dnie-auth-otro", "dnie-firma"]));
}

#[test]
fn local_preferences() {
    let prefs = LocalFilterPrefs::default();
    assert_eq!(prefs.filters(), vec![CertFilter::SkipAuthDnie]);
    let m = CertFilterManager::from_local_prefs(&prefs);
    let mut v: Vec<String> = m.apply(&all(), now()).into_iter().map(|e| e.alias).collect();
    v.sort();
    assert_eq!(v, everything_but(&["dnie-auth", "dnie-auth-otro"]));
    let none = LocalFilterPrefs {
        skip_auth_cert_dnie: false,
        ..Default::default()
    };
    assert!(none.filters().is_empty());
    assert_eq!(
        CertFilterManager::from_local_prefs(&none).apply(&all(), now()).len(),
        all().len()
    );
    let all_on = LocalFilterPrefs {
        use_only_signature_certificates: true,
        skip_auth_cert_dnie: true,
        use_only_alias_certificates: true,
        show_expired_certs: false,
    };
    assert_eq!(
        all_on.filters(),
        vec![CertFilter::Multiple(vec![
            CertFilter::KeyUsage(SIGN_CERT_USAGE),
            CertFilter::SkipAuthDnie,
            CertFilter::Pseudonym { only: true }
        ])]
    );
    let r: Vec<String> = CertFilterManager::from_local_prefs(&all_on)
        .apply(&all(), now())
        .into_iter()
        .map(|e| e.alias)
        .collect();
    assert_eq!(r, vec!["pseudonimo".to_string()]);
}

#[test]
fn cli_filter() {
    let m = CertFilterManager::from_cli_filter("dnie:").unwrap();
    assert_eq!(m.filters(), &[CertFilter::SignatureDnie]);
    // Sin filtro por defecto: los caducados pasan si la expresión no los
    // excluye.
    let m = CertFilterManager::from_cli_filter("subject.contains:CADUCADO").unwrap();
    assert_eq!(m.apply(&all(), now()).len(), 1);
    assert!(CertFilterManager::from_cli_filter("subject.rfc2254:").is_err());
}

#[test]
fn single_certificate_matches() {
    let firma = entry("keystores/filters/dnie-firma.der");
    assert!(CertFilter::SignatureDnie.matches(&firma, now()));
    assert!(CertFilter::Ssl("1122".into()).matches(&firma, now()));
    assert!(!CertFilter::Pseudonym { only: true }.matches(&firma, now()));
    assert!(CertFilter::Multiple(vec![CertFilter::Sscd, CertFilter::SkipAuthDnie]).matches(&firma, now()));
    let mut broken = firma.clone();
    broken.info = None;
    assert!(!CertFilter::Multiple(vec![]).matches(&broken, now()));
}

/// Certificados generados con rcgen: gemelos de seudónimo justo dentro y
/// fuera de la ventana de 60 s, y emisor con diferencias de mayúsculas y
/// espacios (comparación canónica de `X500Principal.equals`).
#[test]
fn pseudonym_twins_with_rcgen() {
    use rcgen::{CertificateParams, DistinguishedName as RDn, DnType, KeyPair, KeyUsagePurpose};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = RDn::new();
    ca_params.distinguished_name.push(DnType::CountryName, "ES");
    ca_params.distinguished_name.push(DnType::OrganizationName, "FNMT-RCM");
    ca_params.distinguished_name.push(DnType::CommonName, "AC Pruebas");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let base = rcgen::date_time_ymd(2034, 5, 5) + std::time::Duration::from_secs(36_000);
    let make = |cn: &str, pseudo: bool, offset_s: i64, ku: Vec<KeyUsagePurpose>| -> CertEntry {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name = RDn::new();
        p.distinguished_name.push(DnType::CountryName, "ES");
        if pseudo {
            p.distinguished_name
                .push(DnType::CustomDnType(vec![2, 5, 4, 65]), "SEUDO-9");
        }
        p.distinguished_name.push(DnType::CommonName, cn);
        p.key_usages = ku;
        // rcgen solo escribe las extensiones si hay alguna otra.
        p.is_ca = rcgen::IsCa::ExplicitNoCa;
        p.not_before = rcgen::date_time_ymd(2024, 1, 1);
        p.not_after = if offset_s >= 0 {
            base + std::time::Duration::from_secs(offset_s as u64)
        } else {
            base - std::time::Duration::from_secs((-offset_s) as u64)
        };
        let c = p.signed_by(&key, &issuer).unwrap();
        let der = c.der().to_vec();
        CertEntry::new(
            cn,
            der.clone(),
            vec![der],
            EntryCapabilities {
                has_private_key: true,
                ..Default::default()
            },
            "rcgen",
        )
    };
    let ku = || vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::ContentCommitment];
    let entries = vec![
        make("seudo", true, 0, ku()),
        make("gemelo-59s", false, 59, ku()),
        make("lejano-60s", false, -60, ku()),
        make("otros-usos", false, 1, vec![KeyUsagePurpose::DigitalSignature]),
    ];
    let _ = ca_cert;
    let m = manager(&[("filters", "pseudonym:")]).unwrap();
    let mut v: Vec<String> = m.apply(&entries, now()).into_iter().map(|e| e.alias).collect();
    v.sort();
    assert_eq!(v, names(&["lejano-60s", "otros-usos", "seudo"]));
}

/// Comparación con la AutoFirma Java: `testdata/keystores/filters/filter-cases.txt`
/// contiene casos (nombre y propiedades) y `filter-java.txt` los alias que
/// acepta `KeyStoreUtilities.getAliasesByFriendlyName` de Java
/// (`tools/oracle/FiltersApplyOracle.java`) con todos los certificados de
/// prueba, sin comprobar claves privadas y mostrando caducados.
#[test]
fn matches_java_golden() {
    let cases = std::fs::read_to_string(testdata().join("keystores/filters/filter-cases.txt")).unwrap();
    let golden = std::fs::read_to_string(testdata().join("keystores/filters/filter-java.txt")).unwrap();
    let golden: std::collections::HashMap<&str, &str> = golden.lines().filter_map(|l| l.split_once('\t')).collect();
    let entries = all();
    let mut checked = 0;
    for line in cases.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let (name, props) = line.split_once('\t').unwrap();
        let props_text = props.replace("<NL>", "\n");
        let params = afirma_core::ExtraParams::parse(&props_text);
        let expected = golden
            .get(name)
            .unwrap_or_else(|| panic!("falta el caso {name} en filter-java.txt"));
        let got = match CertFilterManager::from_extra_params(&params) {
            Err(_) => "ERROR".to_string(),
            Ok(m) => {
                let mut v: Vec<String> = m.apply(&entries, Utc::now()).into_iter().map(|e| e.alias).collect();
                v.sort();
                let mut s = v.join(",");
                s.push_str(&format!(
                    "|mandatory={}|external={}",
                    m.is_mandatory_certificate(),
                    m.allow_external_stores()
                ));
                s
            }
        };
        assert_eq!(&got, expected, "caso {name}: {props}");
        checked += 1;
    }
    assert!(checked > 40, "solo {checked} casos");
}
