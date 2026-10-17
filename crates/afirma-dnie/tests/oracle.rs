//! Prueba cruzada con el simulador Java del oráculo (`tools/oracle/dnie/src/sim/SimCard.java`,
//! escrito y validado contra JMulticard 2.1): el host Rust habla con la tarjeta Java por la
//! entrada y salida estándar (modo `serve`), y la transcripción que registra el lado Java se
//! compara con la de JMulticard (`testdata/dnie/transcript_full.txt`).
//!
//! Desactivada por defecto. Para ejecutarla:
//!
//! ```text
//! export AFIRMA_DNIE_ORACLE=/ruta/de/trabajo     # se compila con tools/oracle/dnie/run.sh
//! cargo test -p afirma-dnie --test oracle -- --nocapture
//! ```
//!
//! Si el directorio no tiene aún las clases de JMulticard se ejecuta
//! `BUILD_ONLY=1 tools/oracle/dnie/run.sh <directorio>` (clona JMulticard y lo compila; requiere
//! git, red y un JDK). `AFIRMA_DNIE_ORACLE_SESSIONS` fija las sesiones PACE de la parte de carga
//! (por defecto 2000).

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use afirma_dnie::{
    CERT_AUTENTICACION, CERT_FIRMA_DIGITAL, CardIdentification, CardTransport, CwaSet, DigestAlgorithm, DnieError,
    DnieSession, TransportError,
};
use common::*;

/// Tarjeta Java en un proceso aparte.
struct JavaSim {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl JavaSim {
    fn spawn(work: &Path, seed: u64, transcript: Option<&Path>) -> JavaSim {
        let cp = std::env::join_paths([work.join("out-rs"), work.join("classes")]).unwrap();
        let mut cmd = Command::new("java");
        cmd.arg("-cp")
            .arg(&cp)
            .args(["sim.Main", "serve"])
            .arg(data_dir())
            .arg(seed.to_string());
        if let Some(t) = transcript {
            cmd.arg(t);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("java");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        JavaSim { child, stdin, stdout }
    }

    fn cmd(&mut self, line: &str) -> Result<String, TransportError> {
        writeln!(self.stdin, "{line}").map_err(|e| TransportError::Io(e.to_string()))?;
        self.stdin.flush().map_err(|e| TransportError::Io(e.to_string()))?;
        let mut out = String::new();
        self.stdout
            .read_line(&mut out)
            .map_err(|e| TransportError::Io(e.to_string()))?;
        if out.is_empty() {
            return Err(TransportError::TagLost("el simulador Java ha terminado".into()));
        }
        Ok(out.trim().to_string())
    }

    fn stats(&mut self) -> String {
        self.cmd("#stats").unwrap()
    }

    fn quit(mut self) {
        let _ = writeln!(self.stdin, "QUIT");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

impl CardTransport for JavaSim {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        let r = self.cmd(&hex::encode_upper(apdu))?;
        hex::decode(&r).map_err(|_| TransportError::Io(format!("respuesta no hexadecimal: {r}")))
    }

    fn identification(&mut self) -> Result<CardIdentification, TransportError> {
        let atr = self.cmd("ATR")?;
        Ok(CardIdentification::from_atr(hex::decode(atr).unwrap_or_default()))
    }
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Compila (si hace falta) JMulticard y el simulador Java en el directorio de trabajo.
fn prepare() -> PathBuf {
    let work = PathBuf::from(std::env::var_os("AFIRMA_DNIE_ORACLE").expect("AFIRMA_DNIE_ORACLE"));
    std::fs::create_dir_all(&work).unwrap();
    if !work.join("classes").is_dir() {
        let st = Command::new(repo().join("tools/oracle/dnie/run.sh"))
            .arg(&work)
            .env("BUILD_ONLY", "1")
            .status()
            .expect("tools/oracle/dnie/run.sh");
        assert!(st.success(), "no se ha podido compilar el oráculo");
    }
    // El simulador se compila siempre (rápido) para tener el modo `serve` actual.
    let srcs: Vec<PathBuf> = std::fs::read_dir(repo().join("tools/oracle/dnie/src/sim"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "java"))
        .collect();
    let st = Command::new("javac")
        .args(["-nowarn", "-encoding", "UTF-8", "-cp"])
        .arg(work.join("classes"))
        .arg("-d")
        .arg(work.join("out-rs"))
        .args(&srcs)
        .status()
        .expect("javac");
    assert!(st.success(), "no se ha podido compilar el simulador Java");
    std::fs::create_dir_all(work.join("transcripts")).unwrap();
    work
}

fn sign_and_check(s: &mut DnieSession<JavaSim>, alias: &str, alg: DigestAlgorithm, data: &[u8], ui: &Recorder) {
    let sig = s.sign(alias, alg, data, ui).unwrap();
    let key = s.key(alias).unwrap();
    let di = alg.digest_info(&alg.digest(data)).unwrap();
    assert!(
        verify_pkcs1(key.public_key(), &di, &sig),
        "firma de {alias} con {alg:?}"
    );
}

#[test]
#[cfg_attr(
    not(afirma_dnie_oracle),
    ignore = "requiere AFIRMA_DNIE_ORACLE=<directorio de trabajo del oráculo>"
)]
fn rust_host_against_java_simcard() {
    let work = prepare();
    let ui = Recorder::new(CAN, &[PIN]);

    // 1. Flujo completo con dos firmas; la transcripción del lado Java debe coincidir con la de
    //    JMulticard (salvo aleatorios).
    let transcript = work.join("transcripts/rust_host_full.txt");
    let java = JavaSim::spawn(&work, 1, Some(&transcript));
    let mut s = DnieSession::open(java, &ui).unwrap();
    assert_eq!(s.info().idesp.as_deref(), Some("BMP100002"));
    assert_eq!(s.info().cwa_set, CwaSet::R2);
    for n in ["1", "2"] {
        sign_and_check(
            &mut s,
            CERT_FIRMA_DIGITAL,
            DigestAlgorithm::Sha256,
            format!("Datos de prueba FIRMA {n}").as_bytes(),
            &ui,
        );
    }
    let stats = s.transport_mut().stats();
    println!("Java tras dos firmas: {stats}");
    assert!(stats.contains("apdus=131") && stats.contains("maxCmd=244") && stats.contains("maxRsp=285"));
    s.close().quit();
    let java_steps: Vec<Step> = parse_java_transcript(&std::fs::read_to_string(&transcript).unwrap())
        .into_iter()
        .map(|(_, s)| s)
        .collect();
    assert_same_steps(&java_steps, &reference_full());
    println!("Transcripción del simulador Java = transcripción de JMulticard (131 APDU)");

    // 2. Constantes r1, SHA-1/384/512 y la clave de autenticación.
    let mut java = JavaSim::spawn(&work, 2, Some(&work.join("transcripts/rust_host_r1.txt")));
    assert_eq!(java.cmd("#idesp AAA000001").unwrap(), "OK");
    let mut s = DnieSession::open(java, &ui).unwrap();
    assert_eq!(s.info().cwa_set, CwaSet::R1);
    sign_and_check(&mut s, CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha512, b"r1 sha512", &ui);
    sign_and_check(&mut s, CERT_AUTENTICACION, DigestAlgorithm::Sha1, b"r1 sha1", &ui);
    sign_and_check(&mut s, CERT_AUTENTICACION, DigestAlgorithm::Sha384, b"r1 sha384", &ui);
    s.close().quit();

    // 3. PIN incorrecto (intentos restantes), SW externa = interna y CAN incorrecto.
    let mut java = JavaSim::spawn(&work, 3, None);
    assert_eq!(java.cmd("#outer63 true").unwrap(), "OK");
    let bad = Recorder::new(CAN, &["0000wxyz", PIN]);
    let mut s = DnieSession::open(java, &bad).unwrap();
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"x", &bad)
        .unwrap_err();
    assert_eq!(e, DnieError::WrongPin { retries_left: Some(2) });
    assert!(s.transport_mut().stats().contains("retries=2"));
    sign_and_check(&mut s, CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"x", &bad);
    assert!(s.transport_mut().stats().contains("retries=3"));
    assert_eq!(
        bad.prompts()[1],
        "Por favor, introduzca el PIN del DNIe.\nIntentos restantes: 2"
    );
    s.close().quit();
    let wrong_can = Recorder::new("654321", &[PIN]);
    let mut java = JavaSim::spawn(&work, 4, None);
    let e = DnieSession::open(&mut java, &wrong_can).err().unwrap();
    assert_eq!(e, DnieError::WrongCan { sw: Some(0x6300) });
    assert!(java.stats().contains("ga4fail=1"));
    java.quit();
}

#[test]
#[cfg_attr(
    not(afirma_dnie_oracle),
    ignore = "requiere AFIRMA_DNIE_ORACLE=<directorio de trabajo del oráculo>"
)]
fn pace_interop_stress_against_java() {
    let work = prepare();
    let total: usize = std::env::var("AFIRMA_DNIE_ORACLE_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let procs = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(2, 8);
    let results: Vec<(usize, usize, usize)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..procs)
            .map(|p| {
                let work = &work;
                scope.spawn(move || {
                    let mut java = JavaSim::spawn(work, 10_000 + p as u64, None);
                    let can = afirma_dnie::PacePassword::can(CAN).unwrap();
                    let mut ok = 0;
                    let n = total / procs + usize::from(p < total % procs);
                    for _ in 0..n {
                        let mut link = afirma_dnie::transport::Link::new(&mut java);
                        let mut tx = |c: &afirma_dnie::CommandApdu| link.transmit(c);
                        let r = afirma_dnie::pace::establish(&mut tx, &can, &mut afirma_dnie::OsRandom).and_then(|o| {
                            let mut sm = o.sm;
                            let w = sm.wrap(&afirma_dnie::fs::select_mf_command())?;
                            let r = link.transmit_bytes(&w)?;
                            sm.unwrap(&r)
                        });
                        match r {
                            Ok(r) if r.is_ok() => ok += 1,
                            other => eprintln!("sesión PACE con Java fallida: {other:?}"),
                        }
                        // SELECT en claro: la tarjeta descarta el contexto para la siguiente sesión.
                        let _ = java.transceive(&afirma_dnie::fs::select_mf_command().encode());
                    }
                    let stats = java.stats();
                    let kx00 = stats
                        .split("kx00=")
                        .nth(1)
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0usize);
                    assert!(stats.contains("ga4fail=0"), "{stats}");
                    java.quit();
                    (n, ok, kx00)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let n: usize = results.iter().map(|r| r.0).sum();
    let ok: usize = results.iter().map(|r| r.1).sum();
    let kx00: usize = results.iter().map(|r| r.2).sum();
    println!("PACE Rust→Java: {n} sesiones, {ok} correctas, {kx00} con K.x empezando por 00");
    assert_eq!(ok, n);
    if n >= 2000 {
        assert!(kx00 > 0);
    }
}
