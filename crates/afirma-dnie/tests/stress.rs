//! Prueba de carga: miles de sesiones PACE con claves aleatorias contra el simulador, sin
//! ningún fallo. Con JMulticard fallan ~1/170 (defecto P1: la X del secreto compartido se
//! codificaba sin los ceros iniciales; el oráculo midió 20 fallos en 3000 sesiones). El número de
//! sesiones se puede cambiar con `AFIRMA_DNIE_STRESS` (por defecto 3000).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use afirma_dnie::fs;
use afirma_dnie::pace::{self, PacePassword};
use afirma_dnie::sm::PaceSm;
use afirma_dnie::transport::Link;
use afirma_dnie::{CERT_FIRMA_DIGITAL, CommandApdu, DigestAlgorithm, DnieSession, OsRandom};
use common::*;

fn sessions() -> usize {
    std::env::var("AFIRMA_DNIE_STRESS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000)
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(2, 16)
}

#[test]
fn pace_stress_random_keys() {
    let total = sessions();
    let next = AtomicUsize::new(0);
    let ok = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    let leading_zero = AtomicUsize::new(0);
    let can = PacePassword::can(CAN).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..threads() {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    // Tarjeta con aleatorios distintos en cada sesión; terminal con OsRandom.
                    let mut card = afirma_dnie::sim::SimCard::from_dir(data_dir(), 1_000_000 + i as u64).unwrap();
                    let result = {
                        let mut link = Link::new(&mut card);
                        let mut tx = |c: &CommandApdu| link.transmit(c);
                        pace::establish(&mut tx, &can, &mut OsRandom).and_then(|out| {
                            // Una APDU protegida comprueba que ambos lados derivaron las mismas
                            // claves.
                            let mut sm: PaceSm = out.sm;
                            let w = sm.wrap(&fs::select_mf_command())?;
                            let r = link.transmit_bytes(&w)?;
                            sm.unwrap(&r)
                        })
                    };
                    match result {
                        Ok(r) if r.is_ok() => {
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        other => {
                            failures.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "sesión {i}: {other:?} (K.x con 00: {})",
                                card.stats.last_kx_leading_zero
                            );
                        }
                    }
                    if card.stats.last_kx_leading_zero {
                        leading_zero.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let (ok, failures, lz) = (ok.into_inner(), failures.into_inner(), leading_zero.into_inner());
    println!("PACE: {total} sesiones, {ok} correctas, {failures} fallos, {lz} con K.x empezando por 00");
    assert_eq!(failures, 0);
    assert_eq!(ok, total);
    if total >= 3000 {
        // Con 3000 sesiones se esperan ~17 con X < 2^248 (probabilidad de ninguna ≈ 2·10⁻⁸): son
        // justo las que fallaban en JMulticard.
        assert!(lz > 0, "ninguna sesión con K.x empezando por 00");
    }
}

#[test]
fn signature_stress() {
    let total = (sessions() / 15).max(20);
    let next = AtomicUsize::new(0);
    let ok = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for t in 0..threads() {
            let next = &next;
            let ok = &ok;
            scope.spawn(move || {
                let ui = Recorder::new(CAN, &[PIN]);
                let card = afirma_dnie::sim::SimCard::from_dir(data_dir(), 500_000 + t as u64).unwrap();
                let mut s = DnieSession::open(card, &ui).unwrap();
                let key = s.key(CERT_FIRMA_DIGITAL).unwrap().clone();
                while next.fetch_add(1, Ordering::Relaxed) < total {
                    let data = format!("datos {t}");
                    let sig = s
                        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, data.as_bytes(), &ui)
                        .unwrap();
                    let di = DigestAlgorithm::Sha256
                        .digest_info(&DigestAlgorithm::Sha256.digest(data.as_bytes()))
                        .unwrap();
                    assert!(verify_pkcs1(key.public_key(), &di, &sig));
                    ok.fetch_add(1, Ordering::Relaxed);
                }
                assert_eq!(s.transport().stats.nested_sm, 0);
            });
        }
    });
    println!("Firmas: {total} pedidas, {} correctas", ok.load(Ordering::Relaxed));
    assert!(ok.load(Ordering::Relaxed) >= total);
}
