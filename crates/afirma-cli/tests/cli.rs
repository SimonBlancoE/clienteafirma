//! Pruebas de extremo a extremo de lo que no se puede comparar sin más con
//! el oráculo Java: desviaciones documentadas (con el golden de Java como
//! referencia), peticiones de interfaz gráfica, `-certgui`, contraseñas sin
//! `-password`, `batchsign` contra un servidor simulado, huellas digitales,
//! comandos de sistema, idiomas y `-version`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use afirma_cli::{
    CertificateChoice, CertificateChooser, CertificateRequest, CliEnv, DoctorRequest, GuiRequest,
    InstallRequest, RestoreRequest, Scope, SystemOps, SystemOutcome, UninstallRequest, run,
};
use afirma_core::http::{HttpClient as CoreHttpClient, HttpClientError, HttpMethod, HttpRequest};
use afirma_keystores::PasswordResponse;
use afirma_keystores::callback::FnPasswordCallback;
use common::*;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn p12(name: &str) -> String {
    format!("pkcs12:{}", td().join(format!("pki/{name}.p12")).display())
}

fn hola() -> String {
    td().join("cades/data/hola.txt").display().to_string()
}

fn env() -> CliEnv {
    env_for(None)
}

const OK: &str = "La operacion ha terminado correctamente \n";

// ---------------------------------------------------------------------------
// Desviaciones documentadas frente al golden de Java

#[test]
fn clave_ausente_en_ingles_usa_el_espanol() {
    let c = case("sign_unknown_alias_en");
    let (java_status, java_text) = golden(&c.name);
    assert_eq!(
        (java_status, java_text.as_str()),
        (255, "!CommandLineLauncher.148!\n")
    );
    let (o, text, _) = run_case(&c);
    assert_eq!(o.status, -1);
    assert_eq!(
        text,
        "No se hay ninguna entrada en el almacen con el alias indicado: nadie\n"
    );
}

#[test]
fn config_sin_igual_da_un_error_claro() {
    let c = case("sign_config_noeq");
    assert_eq!(
        golden(&c.name),
        (
            255,
            "Error no reconocido: Range [0, -1) out of bounds for length 3\n".to_string()
        )
    );
    let (o, text, _) = run_case(&c);
    assert_eq!(o.status, -1);
    assert_eq!(
        text,
        "La configuracion indicada no tiene el formato clave=valor: foo\n"
    );
}

#[test]
fn certgui_sin_selector() {
    let c = case("sign_certgui_nochooser");
    // Java (sin interfaz) termina con error sin imprimir nada.
    assert_eq!(golden(&c.name), (255, String::new()));
    let (o, text, _) = run_case(&c);
    assert_eq!(o.status, -1);
    assert_eq!(text, format!("{}\n", afirma_cli::store::NO_CHOOSER));
}

/// Selector que elige el primer candidato (o cancela).
struct Chooser {
    cancel: bool,
    seen: Mutex<Vec<(usize, bool, String)>>,
}

impl CertificateChooser for Chooser {
    fn choose(&self, request: &CertificateRequest) -> Result<Option<CertificateChoice>, String> {
        let first = request
            .candidates
            .first()
            .map(|e| e.alias.clone())
            .unwrap_or_default();
        self.seen.lock().unwrap().push((
            request.candidates.len(),
            request.allow_external_stores,
            first.clone(),
        ));
        if self.cancel || request.candidates.is_empty() {
            return Ok(None);
        }
        Ok(Some(CertificateChoice {
            store: request.store.clone(),
            alias: first,
        }))
    }
}

#[test]
fn certgui_con_selector() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("o.csig");
    let chooser = Arc::new(Chooser {
        cancel: false,
        seen: Mutex::new(Vec::new()),
    });
    let env = env().with_certificate_chooser(chooser.clone());
    let args = s(&[
        "sign",
        "-i",
        &hola(),
        "-o",
        out.to_str().unwrap(),
        "-certgui",
        "-store",
        &p12("firmante-rsa"),
        "-password",
        "12341234",
        "-config",
        "filters=disableopeningexternalstores;subject.contains:JUAN",
    ]);
    let o = run(&args, &env);
    assert_eq!(
        (o.status, o.output.as_str()),
        (0, OK),
        "{:?}",
        chooser.seen.lock().unwrap()
    );
    assert_eq!(
        chooser.seen.lock().unwrap().as_slice(),
        &[(1, false, "firmante-rsa".to_string())]
    );
    let tree = structure(&std::fs::read(&out).unwrap()).1;
    assert_eq!(
        tree,
        vec![(0, "ESPAÑOL ESPAÑOL JUAN - 00000000T".to_string())]
    );

    // -filter sustituye a los filtros de -config.
    let chooser = Arc::new(Chooser {
        cancel: false,
        seen: Mutex::new(Vec::new()),
    });
    let env2 = env_for(None).with_certificate_chooser(chooser.clone());
    let mut args2 = args.clone();
    args2.extend(s(&["-filter", "subject.contains:NADIE"]));
    let o = run(&args2, &env2);
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            -1,
            "Error no reconocido: No se ha seleccionado certificado\n"
        )
    );
    // Sin candidatos el selector recibe la lista vacía (el diálogo avisaría).
    assert_eq!(chooser.seen.lock().unwrap()[0].0, 0);

    // Cancelación: AOCancelledOperationException -> error no reconocido.
    let env3 = env_for(None).with_certificate_chooser(Arc::new(Chooser {
        cancel: true,
        seen: Mutex::new(Vec::new()),
    }));
    let o = run(&args, &env3);
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            -1,
            "Error no reconocido: No se ha seleccionado certificado\n"
        )
    );
    let mut xml = args.clone();
    xml.push("-xml".into());
    let o = run(&xml, &env3);
    assert_eq!(
        o.output,
        "<afirma><result>false</result><response><msg>Error no reconocido: No se ha seleccionado certificado</msg></response></afirma>\n"
    );
}

#[test]
fn sin_password_se_usa_el_proveedor_de_la_aplicacion() {
    let c = case("list_no_password");
    // Java (sin interfaz) carga el PKCS#12 sin contraseña y lista los alias.
    assert_eq!(golden(&c.name), (0, "firmante-rsa\n\n".to_string()));
    // Sin proveedor interactivo no hay contraseña.
    let (o, text, _) = run_case(&c);
    assert_eq!(
        (o.status, text.as_str()),
        (-1, "La contrasena del almacen PKCS#12 / PFX no es valida\n")
    );
    // Con el proveedor de la aplicación (diálogo de contraseña).
    let asked = Arc::new(Mutex::new(Vec::new()));
    let asked2 = asked.clone();
    let cb = FnPasswordCallback(move |req: &afirma_keystores::PasswordRequest| {
        asked2.lock().unwrap().push(req.prompt.clone());
        PasswordResponse::provided("12341234")
    });
    let env = env().with_password_callback(Arc::new(cb));
    let o = run(&s(&["listaliases", "-store", &p12("firmante-rsa")]), &env);
    assert_eq!((o.status, o.output.as_str()), (0, "firmante-rsa\n\n"));
    assert_eq!(asked.lock().unwrap().len(), 1);
}

#[test]
fn ooxml_sin_interfaz() {
    // Java no puede firmar OOXML sin interfaz gráfica (HeadlessException).
    let c = case("sign_ooxml");
    assert_eq!(
        golden(&c.name),
        (
            255,
            "Error durante la firma OOXML: java.awt.HeadlessException\n".to_string()
        )
    );
    let (o, text, out) = run_case(&c);
    assert_eq!((o.status, text.as_str()), (0, OK));
    let sig = std::fs::read(out.path().join("out.docx")).unwrap();
    let (kind, tree, _) = structure(&sig);
    assert!(kind.eq_ignore_ascii_case("ooxml"), "{kind}");
    assert_eq!(
        tree,
        vec![(0, "ESPAÑOL ESPAÑOL JUAN - 00000000T".to_string())]
    );
    dump("sign_ooxml", ".docx", &sig);
    // verify: validación incompleta (como un OOXML firmado en Java).
    let o = run(
        &s(&[
            "verify",
            "-i",
            out.path().join("out.docx").to_str().unwrap(),
        ]),
        &env(),
    );
    assert_eq!(o.output, golden("verify_word_signed").1);
}

// ---------------------------------------------------------------------------
// batchsign

/// Servidor trifásico simulado.
struct MockServer {
    requests: Mutex<Vec<(String, String)>>,
    fail_post: bool,
}

impl CoreHttpClient for MockServer {
    fn read_url(&self, req: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
        assert_eq!(req.method, HttpMethod::Post);
        let (url, body) = afirma_core::http::split_post_url(&req.url);
        let body = body.unwrap_or_default();
        self.requests
            .lock()
            .unwrap()
            .push((url.clone(), body.clone()));
        let pre = afirma_core::base64_encode(b"datos a firmar");
        let json = body.starts_with("json=");
        if url.ends_with("/pre") {
            return Ok(if json {
                format!("{{\"td\":{{\"format\":\"CAdES\",\"signs\":[{{\"signinfo\":[{{\"id\":\"1\",\"params\":{{\"PRE\":\"{pre}\"}}}}]}}]}}}}").into_bytes()
            } else {
                format!("<xml><firmas format=\"CAdES\"><firma Id=\"1\"><param n=\"PRE\">{pre}</param></firma></firmas></xml>").into_bytes()
            });
        }
        if self.fail_post {
            return Err(HttpClientError::Io {
                url,
                message: "conexion rehusada".into(),
            });
        }
        Ok(if json {
            b"{\"signs\":[{\"id\":\"1\",\"result\":\"DONE_AND_SAVED\"}]}".to_vec()
        } else {
            b"<signs><signresult id=\"1\" result=\"DONE_AND_SAVED\"/></signs>".to_vec()
        })
    }
}

fn batch_env(fail_post: bool) -> (CliEnv, Arc<MockServer>) {
    let server = Arc::new(MockServer {
        requests: Mutex::new(Vec::new()),
        fail_post,
    });
    let mut env = env();
    env.http = Some(afirma_protocol::HttpClient::new(server.clone()));
    (env, server)
}

fn batch_args(input: &Path, out: Option<&Path>, extra: &[&str]) -> Vec<String> {
    let mut a = s(&[
        "batchsign",
        "-i",
        input.to_str().unwrap(),
        "-store",
        &p12("firmante-rsa"),
        "-password",
        "12341234",
        "-alias",
        "firmante-rsa",
    ]);
    if let Some(o) = out {
        a.extend(s(&["-o", o.to_str().unwrap()]));
    }
    a.extend(s(&[
        "-preurl",
        "http://servidor/pre",
        "-posturl",
        "http://servidor/post",
    ]));
    a.extend(s(extra));
    a
}

#[test]
fn batchsign_xml_y_json() {
    let dir = tempfile::tempdir().unwrap();
    let xml_batch = dir.path().join("lote.xml");
    std::fs::write(&xml_batch, br#"<?xml version="1.0" encoding="UTF-8"?><signbatch stoponerror="false" algorithm="SHA256withRSA"><singlesign Id="1"><datasource>aG9sYQ==</datasource><format>CAdES</format><suboperation>sign</suboperation></singlesign></signbatch>"#).unwrap();
    let out = dir.path().join("resultado.xml");
    let (env, server) = batch_env(false);
    let o = run(&batch_args(&xml_batch, Some(&out), &[]), &env);
    assert_eq!((o.status, o.output.as_str()), (0, OK));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "<signs><signresult id=\"1\" result=\"DONE_AND_SAVED\"/></signs>"
    );
    let reqs = server.requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 2);
    assert!(
        reqs[0].1.starts_with("xml=") && reqs[0].1.contains("&certs="),
        "{}",
        reqs[0].1
    );
    assert!(reqs[1].1.contains("&tridata="), "{}", reqs[1].1);

    // Lote en Base64: se decodifica antes de enviarlo.
    let b64 = dir.path().join("lote.b64");
    std::fs::write(
        &b64,
        afirma_core::base64_encode(&std::fs::read(&xml_batch).unwrap()),
    )
    .unwrap();
    let (env, server) = batch_env(false);
    let o = run(&batch_args(&b64, None, &["-xml"]), &env);
    assert_eq!(o.status, 0, "{}", o.output);
    assert_eq!(
        mask_sign(&o.output),
        "<afirma><result>true</result><response><msg>La operacion ha terminado correctamente </msg><sign>@SIGN@</sign></response></afirma>\n"
    );
    assert_eq!(
        xml_sign(&o.output).unwrap(),
        b"<signs><signresult id=\"1\" result=\"DONE_AND_SAVED\"/></signs>"
    );
    assert_eq!(server.requests.lock().unwrap()[0].1, reqs[0].1);

    // Lote JSON.
    let json_batch = dir.path().join("lote.json");
    std::fs::write(&json_batch, br#"{"algorithm":"SHA256withRSA","format":"CAdES","suboperation":"sign","singlesigns":[{"id":"1","datareference":"aG9sYQ=="}]}"#).unwrap();
    let (env, server) = batch_env(false);
    let o = run(&batch_args(&json_batch, Some(&out), &[]), &env);
    assert_eq!((o.status, o.output.as_str()), (0, OK));
    assert!(server.requests.lock().unwrap()[0].1.starts_with("json="));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "{\"signs\":[{\"id\":\"1\",\"result\":\"DONE_AND_SAVED\"}]}"
    );
}

#[test]
fn batchsign_errores_con_estado() {
    let dir = tempfile::tempdir().unwrap();
    let batch = td().join("cades/data/documento.xml");
    let out = dir.path().join("r.xml");
    // El XML no es un lote: Java lo descartaba y salía con 0.
    let (env, _) = batch_env(false);
    let o = run(&batch_args(&batch, Some(&out), &[]), &env);
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            -1,
            "El lote proporcionado no es un XML bien formado o no tiene la estructura correcta\n"
        )
    );

    // Error de red en la postfirma, en XML.
    let lote = dir.path().join("lote.xml");
    std::fs::write(&lote, br#"<signbatch algorithm="SHA512withRSA"/>"#).unwrap();
    let (env, _) = batch_env(true);
    let o = run(&batch_args(&lote, Some(&out), &["-xml"]), &env);
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            -1,
            "<afirma><result>false</result><response><msg>Error en la llamada al servicio de postfirma de lotes XML</msg></response></afirma>\n"
        )
    );

    // Casos del oráculo en los que Java no imprimía nada y salía con 0.
    for name in [
        "batch_conn_error",
        "batch_bad_password",
        "batch_xml_no_output",
    ] {
        assert_eq!(golden(name), (0, String::new()), "{name}");
    }
    let (o, text, _) = run_case(&case("batch_conn_error"));
    assert_eq!(
        (o.status, text.as_str()),
        (
            -1,
            "El lote proporcionado no es un XML bien formado o no tiene la estructura correcta\n"
        )
    );
    // Servicio inaccesible (puerto 9 local) con un lote válido.
    let o = run(
        &batch_args(&lote, Some(&out), &[])
            .into_iter()
            .map(|a| a.replace("http://servidor", "http://127.0.0.1:9"))
            .collect::<Vec<_>>(),
        &env_for(None),
    );
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            -1,
            "Error en la llamada al servicio de prefirma de lotes XML\n"
        )
    );
    let (o, text, _) = run_case(&case("batch_bad_password"));
    assert_eq!(
        (o.status, text.as_str()),
        (-1, "La contrasena del almacen PKCS#12 / PFX no es valida\n")
    );
    let (o, text, _) = run_case(&case("batch_xml_no_output"));
    assert_eq!(o.status, -1);
    assert_eq!(
        text,
        "<afirma><result>false</result><response><msg>El lote proporcionado no es un XML bien formado o no tiene la estructura correcta</msg></response></afirma>\n"
    );
}

// ---------------------------------------------------------------------------
// Interfaz gráfica

#[test]
fn peticiones_de_interfaz() {
    let o = run(
        &s(&[
            "sign",
            "-gui",
            "-i",
            &hola(),
            "-format",
            "PAdES",
            "-config",
            "a=1\\nb = 2\nmal",
            "-algorithm",
            "sha256",
        ]),
        &env(),
    );
    assert_eq!((o.status, o.output.as_str()), (0, ""));
    let Some(GuiRequest::Sign(req)) = o.gui else {
        panic!("{o:?}")
    };
    assert_eq!(req.file, PathBuf::from(hola()));
    assert_eq!(req.operation, afirma_cli::GuiOperation::Sign);
    assert_eq!(req.format.as_deref(), Some("PAdES"));
    assert_eq!(req.extra_params.get("a"), Some("1"));
    assert_eq!(req.extra_params.get("b"), Some("2"));
    assert_eq!(req.extra_params.len(), 2);
    assert_eq!(
        (req.digest_algorithm.as_str(), req.algorithm_explicit),
        ("SHA-256", true)
    );

    let o = run(&s(&["SIGN", "-gui", "-i", &hola()]), &env());
    let Some(GuiRequest::Sign(req)) = o.gui else {
        panic!("{o:?}")
    };
    assert_eq!(
        (
            req.format,
            req.digest_algorithm.as_str(),
            req.algorithm_explicit
        ),
        (None, "SHA-512", false)
    );

    let o = run(&s(&["verify", "-gui", "-i", &hola()]), &env());
    assert_eq!(
        o.gui,
        Some(GuiRequest::Verify {
            file: PathBuf::from(hola())
        })
    );

    // Sin -i: diálogo de error, mensaje y estado -1 (sin ayuda: CommandLineException).
    for cmd in ["sign", "verify"] {
        let o = run(&s(&[cmd, "-gui"]), &env());
        assert_eq!(
            (o.status, o.output.as_str()),
            (-1, "No se ha especificado un fichero de entrada\n"),
            "{cmd}"
        );
        assert_eq!(
            o.gui,
            Some(GuiRequest::ErrorDialog {
                title: "Error en los parámetros de entrada".into(),
                message: "No se ha especificado un fichero de entrada".into()
            })
        );
    }
    // Error de parámetro tras -gui: diálogo y ayuda.
    let o = run(&s(&["sign", "-gui", "-format", "foo"]), &env());
    assert!(
        o.output
            .starts_with("Formato de firma no soportado: foo\nSintaxis: autofirma.jar sign"),
        "{}",
        o.output
    );
    assert!(
        matches!(o.gui, Some(GuiRequest::ErrorDialog { ref message, .. }) if message == "Formato de firma no soportado: foo")
    );
    // Antes de -gui no hay diálogo (depende del orden, como en Java).
    let o = run(&s(&["sign", "-foo", "-gui"]), &env());
    assert_eq!(
        (o.output.as_str(), o.gui),
        ("No se reconoce el parametro -foo\n", None)
    );
    // cosign ignora -gui.
    let o = run(&s(&["cosign", "-gui", "-i", &hola()]), &env());
    assert!(o.gui.is_none() && o.status == -1);
}

// ---------------------------------------------------------------------------
// Huellas digitales (createdigest / checkdigest)

#[test]
fn huellas_digitales() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.txt");
    std::fs::write(&f, b"hola").unwrap();
    let o = run(&s(&["createdigest", f.to_str().unwrap()]), &env());
    // SHA-256("hola") en hexadecimal en mayúsculas seguido de 'h'.
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            0,
            "B221D9DBB083A7F33428D7C2A3C3198AE925614D70210E28716CCAA7CD4DDB79h\n"
        )
    );
    let hash = dir.path().join("a.txt.hexhash");
    let o = run(
        &s(&[
            "CreateDigest",
            f.to_str().unwrap(),
            "-o",
            hash.to_str().unwrap(),
        ]),
        &env(),
    );
    assert_eq!((o.status, o.output.as_str()), (0, OK));
    let o = run(
        &s(&[
            "checkdigest",
            f.to_str().unwrap(),
            "-i",
            hash.to_str().unwrap(),
        ]),
        &env(),
    );
    assert_eq!(
        (o.status, o.output.as_str()),
        (0, "Comprobacion de huella digital finalizada sin errores\n")
    );
    std::fs::write(&f, b"adios").unwrap();
    let o = run(
        &s(&[
            "checkdigest",
            f.to_str().unwrap(),
            "-i",
            hash.to_str().unwrap(),
        ]),
        &env(),
    );
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            1,
            "Las huellas indicadas no se corresponden con las del archivo de entrada\n"
        )
    );
    let mut java_env = env();
    java_env.hash_java_exit_codes = true;
    let o = run(
        &s(&[
            "checkdigest",
            f.to_str().unwrap(),
            "-i",
            hash.to_str().unwrap(),
        ]),
        &java_env,
    );
    assert_eq!(o.status, 0);
    let o = run(&s(&["createdigest", f.to_str().unwrap(), "-gui"]), &env());
    assert!(
        matches!(
            o.gui,
            Some(GuiRequest::Hash(
                afirma_hash::GuiRequest::CreateDigest { .. }
            ))
        ),
        "{o:?}"
    );
    let o = run(&s(&["createdigest"]), &env());
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            -1,
            "Error no reconocido: No se ha indicado ningun fichero o directorio\n"
        )
    );
    let o = run(&s(&["checkdigest"]), &env());
    assert!(
        o.status == 0 && o.output.starts_with("Sintaxis:\n  Autofirma checkdigest"),
        "{}",
        o.output
    );
}

// ---------------------------------------------------------------------------
// Comandos de sistema

#[derive(Default)]
struct MockSystem {
    calls: Mutex<Vec<String>>,
}

impl SystemOps for MockSystem {
    fn install(&self, r: &InstallRequest) -> SystemOutcome {
        self.calls.lock().unwrap().push(format!("{r:?}"));
        SystemOutcome {
            status: 0,
            output: "instalado\n".into(),
        }
    }
    fn uninstall(&self, r: &UninstallRequest) -> SystemOutcome {
        self.calls.lock().unwrap().push(format!("{r:?}"));
        SystemOutcome {
            status: -1,
            output: "fallo".into(),
        }
    }
    fn doctor(&self, r: &DoctorRequest) -> SystemOutcome {
        self.calls.lock().unwrap().push(format!("{r:?}"));
        SystemOutcome {
            status: 1,
            output: "{}".into(),
        }
    }
    fn restore_config(&self, r: &RestoreRequest) -> SystemOutcome {
        self.calls.lock().unwrap().push(format!("{r:?}"));
        SystemOutcome {
            status: 0,
            output: String::new(),
        }
    }
}

#[test]
fn comandos_de_sistema() {
    let ops = Arc::new(MockSystem::default());
    let env = env().with_system(ops.clone());
    let o = run(
        &s(&[
            "install",
            "--system",
            "--origins",
            "https://sede.example.es",
            "--dry-run",
        ]),
        &env,
    );
    assert_eq!((o.status, o.output.as_str()), (0, "instalado\n"));
    let o = run(&s(&["uninstall", "--user"]), &env);
    assert_eq!((o.status, o.output.as_str()), (-1, "fallo\n"));
    let o = run(&s(&["doctor", "--json"]), &env);
    assert_eq!((o.status, o.output.as_str()), (1, "{}\n"));
    let o = run(&s(&["Restore-Config"]), &env);
    assert_eq!((o.status, o.output.as_str()), (0, "\n"));
    assert_eq!(
        ops.calls.lock().unwrap().as_slice(),
        &[
            format!(
                "{:?}",
                InstallRequest {
                    scope: Scope::System,
                    browser_policies: true,
                    origins: vec!["https://sede.example.es".into()],
                    dry_run: true
                }
            ),
            format!(
                "{:?}",
                UninstallRequest {
                    scope: Scope::User,
                    dry_run: false
                }
            ),
            format!("{:?}", DoctorRequest { json: true }),
            format!("{:?}", RestoreRequest),
        ]
    );
    // Errores de sintaxis: mensaje y ayuda, sin llamar a la implementación.
    let o = run(&s(&["install"]), &env);
    assert_eq!(o.status, -1);
    assert!(o.output.starts_with("Se tiene que indicar una de las opciones '--system' o '--user'\nSintaxis: autofirma.jar install"), "{}", o.output);
    assert_eq!(ops.calls.lock().unwrap().len(), 4);
    let o = run(&s(&["install", "-help"]), &env);
    assert!(
        o.status == 0 && o.output.contains("--browser-policies"),
        "{}",
        o.output
    );
    // Sin implementación conectada.
    let o = run(&s(&["doctor"]), &env_for(None));
    assert_eq!(
        (o.status, o.output.as_str()),
        (
            -1,
            "La integracion con el sistema no esta disponible en esta version\n"
        )
    );
}

// ---------------------------------------------------------------------------
// Idiomas, -version y XML

#[test]
fn idioma_por_preferencia_o_sistema() {
    let mut env = env_for(None);
    env.os_locale = Some("ca_ES.UTF-8".into());
    let o = run(&s(&["-help"]), &env);
    assert!(
        o.output.starts_with("Eina de signatura de documents."),
        "{}",
        o.output
    );
    // La preferencia manda sobre el sistema.
    let mut env = env_for(Some("gl_ES"));
    env.os_locale = Some("en_US".into());
    assert!(
        run(&s(&["-help"]), &env)
            .output
            .starts_with("Ferramenta de sinatura de documentos.")
    );
    // Idioma sin catálogo: español.
    let mut env = env_for(None);
    env.os_locale = Some("fr_FR".into());
    assert!(
        run(&s(&[]), &env)
            .output
            .starts_with("Herramienta de firma de documentos.")
    );
    // Validación en inglés.
    let o = run(&s(&["verify", "-i", &hola()]), &env_for(Some("en_US")));
    assert_eq!(
        o.output,
        "Invalid signature: No signature found within document\n\n"
    );
}

#[test]
fn version_y_xml_escapado() {
    assert_eq!(run(&s(&["--help"]), &env()), run(&s(&["-HELP"]), &env()));
    let o = run(&s(&["--version"]), &env());
    assert_eq!(
        (o.status, o.output),
        (0, format!("AutoFirma {}\n", env!("CARGO_PKG_VERSION")))
    );
    // Los mensajes se escapan en XML (Java no lo hacía).
    let o = run(&s(&["sign", "-i", "/no/<existe>&", "-xml"]), &env());
    assert_eq!(
        o.output,
        "<afirma><result>false</result><response><msg>El fichero de entrada no existe: /no/&lt;existe&gt;&amp;</msg></response></afirma>\n"
    );
}

#[test]
fn reintento_sin_firma_visible_conserva_la_configuracion() {
    // Java perdía la primera línea no visible (concatenada a `null`); aquí se conserva.
    let c = case("sign_pades_badpage");
    let (o, _, out) = run_case(&c);
    assert_eq!(o.status, 0, "{}", o.output);
    let pdf = std::fs::read(out.path().join("out.pdf")).unwrap();
    let text = String::from_utf8_lossy(&pdf);
    assert!(
        text.contains("/Reason (Prueba)") || text.contains("/Reason(Prueba)"),
        "sin /Reason"
    );
}
