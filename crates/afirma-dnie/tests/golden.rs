//! Paridad de transcripción con JMulticard: el host Rust contra el simulador Rust envía la misma
//! secuencia de APDU que JMulticard 2.1 contra el simulador Java (`testdata/dnie/transcript_*.txt`):
//! mismo contexto de mensajería segura en cada paso, mismos comandos internos (salvo aleatorios),
//! mismas longitudes en el aire y mismas SW.

mod common;

use afirma_dnie::{CERT_FIRMA_DIGITAL, DigestAlgorithm, DnieError, DnieSession};
use common::*;

fn sign(s: &mut DnieSession<afirma_dnie::sim::SimCard>, label: &str, ui: &Recorder) -> Result<Vec<u8>, DnieError> {
    let data = format!("Datos de prueba {label}");
    s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, data.as_bytes(), ui)
}

#[test]
fn transcript_matches_jmulticard() {
    // Carga + dos firmas (constantes r2).
    let reference = reference_full();
    assert_eq!(reference.len(), 56 + 35 + 40);
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = DnieSession::open(sim(42), &ui).unwrap();
    sign(&mut s, "FIRMA 1", &ui).unwrap();
    sign(&mut s, "FIRMA 2", &ui).unwrap();
    assert_same_steps(&steps_from_sim(s.transport().transcript()), &reference);
}

#[test]
fn transcript_r1_matches_jmulticard() {
    // IDESP anterior a BMP100001 (constantes r1); también sin la relectura del IDESP del arnés.
    let reference = reference("transcript_r1.txt", 57..=59);
    let mut card = sim(43);
    card.idesp = b"AAA000001".to_vec();
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = DnieSession::open(card, &ui).unwrap();
    sign(&mut s, "FIRMA r1", &ui).unwrap();
    assert_same_steps(&steps_from_sim(s.transport().transcript()), &reference);
}

#[test]
fn transcript_outer_sw_matches_jmulticard() {
    // Respuestas CWA con la SW externa igual a la interna.
    let reference = reference("transcript_outer63.txt", 0..=0);
    let mut card = sim(44);
    card.cwa_outer_sw_equals_inner = true;
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = DnieSession::open(card, &ui).unwrap();
    sign(&mut s, "FIRMA (SW exterior = interior)", &ui).unwrap();
    assert_same_steps(&steps_from_sim(s.transport().transcript()), &reference);
}

#[test]
fn transcript_wrong_pin_matches_jmulticard_until_verify() {
    // Hasta el VERIFY erróneo (APDU 73) es igual; después JMulticard deja abierto el canal de PIN y
    // en el segundo intento envía MSE:SET DST + PSO:CDS por él (6982), mientras que aquí se
    // descarta el contexto con el SELECT en claro (§8.3).
    let reference = reference("transcript_wrongpin.txt", 0..=0);
    assert_eq!(reference.len(), 75);
    let ui = Recorder::new(CAN, &["0000wxyz"]);
    let mut s = DnieSession::open(sim(45), &ui).unwrap();
    let e = sign(&mut s, "FIRMA con PIN erroneo", &ui).unwrap_err();
    assert_eq!(e, DnieError::WrongPin { retries_left: Some(2) });
    let ours = steps_from_sim(s.transport().transcript());
    assert_same_steps(&ours[..73], &reference[..73]);
    assert_eq!(ours[73].inner, "00A404000B4D61737465722E46696C65");
    assert_eq!(ours[73].inner_sw, Some(0x6987));
    assert_eq!(ours.len(), 74);
}
