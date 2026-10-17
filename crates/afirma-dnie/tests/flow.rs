//! Flujo completo contra el simulador de DNIe: detección → PACE → certificados → PIN → firma,
//! errores (CAN, PIN, bloqueo, retirada de la tarjeta, pérdida del canal) y longitudes de la
//! especificación 10 §11.

mod common;

use afirma_dnie::atr::{DetectionEvidence, DetectionPolicy};
use afirma_dnie::sim::SimCard;
use afirma_dnie::{
    CERT_AUTENTICACION, CERT_FIRMA_DIGITAL, CardIdentification, CwaSet, DigestAlgorithm, DnieError, DnieSession,
    ErrorCategory, FixedInteraction, OsRandom, SessionOptions, TransportError,
};
use common::*;

fn open(sim: SimCard, ui: &Recorder) -> Result<DnieSession<SimCard>, DnieError> {
    DnieSession::open(sim, ui)
}

/// Comandos internos (desprotegidos o en claro) de la transcripción, con su contexto.
fn inner_commands(s: &SimCard) -> Vec<(&'static str, Vec<u8>)> {
    s.transcript()
        .iter()
        .map(|t| (t.context, t.inner.clone().unwrap_or_else(|| t.command.clone())))
        .collect()
}

#[test]
fn full_flow_two_signatures() {
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = open(sim(1), &ui).unwrap();
    assert_eq!(*ui.can_requests.lock().unwrap(), 1);
    // §11.2: 5 APDU de PACE + 51 bajo PACE con los ficheros del espécimen.
    assert_eq!(s.apdu_count(), 56);
    assert_eq!(s.transport().transcript().len(), 56);
    assert!(matches!(s.info().evidence, DetectionEvidence::Atr(_)));
    assert_eq!(s.info().idesp.as_deref(), Some("BMP100002"));
    assert_eq!(s.info().cwa_set, CwaSet::R2);
    let aliases: Vec<&str> = s.keys().iter().map(|k| k.alias.as_str()).collect();
    assert_eq!(aliases, vec![CERT_AUTENTICACION, CERT_FIRMA_DIGITAL]);
    let k = s.key(CERT_FIRMA_DIGITAL).unwrap().clone();
    assert_eq!(k.key_label, "KprivFirmaDigital");
    assert_eq!(k.key_fid(), [0x01, 0x02]);
    assert_eq!(k.key_reference, Some(2));
    assert_eq!(k.key_bits, 2048);
    assert_eq!(
        k.chain.len(),
        2,
        "certificado + CA intermedia (el simulador no tiene raíz del DNIe)"
    );
    assert_eq!(s.intermediate_certificate().map(<[u8]>::len), Some(747));
    assert_eq!(s.context_name(), "PACE");

    // Primera firma (SHA-256): 35 APDU (§11.3).
    let data = b"Datos de prueba FIRMA 1";
    let sig1 = s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, data, &ui).unwrap();
    assert_eq!(sig1.len(), 256);
    let di = DigestAlgorithm::Sha256
        .digest_info(&DigestAlgorithm::Sha256.digest(data))
        .unwrap();
    assert!(verify_pkcs1(k.public_key(), &di, &sig1));
    assert_eq!(s.apdu_count(), 56 + 35);
    assert_eq!(s.context_name(), "sin SM");
    assert_eq!(s.transport().context_name(), "sin SM");

    // Segunda firma (SHA-512): PACE de nuevo + 35 = 40 APDU (§11.4); no se vuelve a pedir el CAN.
    let sig2 = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha512, b"otra", &ui)
        .unwrap();
    let di = DigestAlgorithm::Sha512
        .digest_info(&DigestAlgorithm::Sha512.digest(b"otra"))
        .unwrap();
    assert!(verify_pkcs1(k.public_key(), &di, &sig2));
    assert_eq!(s.apdu_count(), 56 + 35 + 40);
    assert_eq!(*ui.can_requests.lock().unwrap(), 1);
    assert_eq!(
        ui.prompts(),
        vec![
            "Por favor, introduzca el PIN del DNIe.\nIntentos restantes: 3".to_string(),
            "Por favor, introduzca el PIN del DNIe.\nIntentos restantes: 3".to_string()
        ]
    );

    let card = s.transport();
    let st = &card.stats;
    assert_eq!(st.pace_sessions, 2);
    assert_eq!(st.signatures, 2);
    assert_eq!(st.nested_sm, 0, "nunca hay doble envoltura");
    assert_eq!(st.plain_with_sm, 2, "un SELECT en claro de «reset» tras cada firma");
    // §11.5: C-APDU máxima 244 (PSO:VERIFY CERTIFICATE bajo PACE), R-APDU máxima 285 (firma).
    assert_eq!(st.max_command, 244);
    assert_eq!(st.max_response, 285);
    assert!(!st.envelope_used);
}

#[test]
fn layering_matches_spec() {
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = open(sim(2), &ui).unwrap();
    s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"x", &ui).unwrap();
    let card = s.transport();
    let t = card.transcript();
    let cmds = inner_commands(card);
    // Fase A: PACE en claro, exactamente como JMulticard.
    assert_eq!(
        hex::encode_upper(&t[0].command),
        "0022C1A412800A04007F0007020204020283010284010D"
    );
    assert_eq!(hex::encode_upper(&t[1].command), "10860000027C00");
    assert_eq!(&t[2].command[..9], &hex::decode("10860000457C438141").unwrap()[..]);
    assert_eq!(&t[3].command[..9], &hex::decode("10860000457C438341").unwrap()[..]);
    assert_eq!(&t[4].command[..9], &hex::decode("008600000C7C0A8508").unwrap()[..]);
    assert!(t[..5].iter().all(|e| e.context == "sin SM"));
    // Fase B (bajo PACE): SELECT MF ×2, 5015, 6004 y lecturas de 222 octetos.
    let hexs: Vec<String> = cmds.iter().map(|(_, c)| hex::encode_upper(c)).collect();
    assert_eq!(hexs[5], "00A404000B4D61737465722E46696C65");
    assert_eq!(hexs[6], "00A404000B4D61737465722E46696C65");
    assert_eq!(hexs[7], "00A40000025015");
    assert_eq!(hexs[8], "00A40000026004");
    assert_eq!(hexs[9], "00B00000DE");
    // Bajo PACE las APDU protegidas llevan Le = 00 final; bajo CWA, no.
    for e in t.iter().filter(|e| e.inner.is_some()) {
        let total = 5 + e.command[4] as usize;
        match e.context {
            "PACE" => assert_eq!(e.command.len(), total + 1),
            _ => assert_eq!(e.command.len(), total),
        }
    }
    // IDESP leído una vez (56 APDU) y contexto de cada operación de la firma.
    let find = |prefix: &str| {
        cmds.iter()
            .enumerate()
            .filter(|(_, (_, c))| hex::encode_upper(c).starts_with(prefix))
            .map(|(i, (ctx, _))| (i, *ctx))
            .collect::<Vec<_>>()
    };
    assert_eq!(find("00A40000020006").len(), 1);
    let gci = find("90B8000007");
    assert_eq!(gci.iter().map(|x| x.1).collect::<Vec<_>>(), vec!["PACE", "CWA-PIN"]);
    let mse_at = find("0022C1A412830C00000000");
    assert_eq!(mse_at.iter().map(|x| x.1).collect::<Vec<_>>(), vec!["PACE", "CWA-PIN"]);
    // Juego r2: CHR del terminal de PIN y de usuario.
    assert!(hexs[mse_at[0].0].contains("D002E00000000004"));
    assert!(hexs[mse_at[1].0].contains("D002E00000000002"));
    let retries = find("0020000000");
    assert_eq!(retries, vec![(retries[0].0, "CWA-PIN")]);
    let verify = find("00200000083132333461626364");
    assert_eq!(verify.len(), 1);
    assert_eq!(verify[0].1, "CWA-PIN");
    assert_eq!(
        find("002241B60484020102").iter().map(|x| x.1).collect::<Vec<_>>(),
        vec!["CWA-USR"]
    );
    let pso = find("002A9E9A333031300D060960864801650304020105000420");
    assert_eq!(pso.iter().map(|x| x.1).collect::<Vec<_>>(), vec!["CWA-USR"]);
    // Último: SELECT MF en claro con el canal de usuario activo → 6987.
    let last = t.last().unwrap();
    assert_eq!(hex::encode_upper(&last.command), "00A404000B4D61737465722E46696C65");
    assert_eq!(last.context, "CWA-USR");
    assert_eq!(hex::encode_upper(&last.response), "6987");
    // Longitudes en el aire de la firma (§11.3): PSO:CDS de 74 y respuesta de 285.
    let pso_air = &t[pso[0].0];
    assert_eq!(pso_air.command.len(), 74);
    assert_eq!(pso_air.response.len(), 285);
    assert_eq!(&pso_air.response[..5], &[0x87, 0x82, 0x01, 0x09, 0x01]);
}

#[test]
fn r1_constants_by_idesp() {
    let mut card = sim(3);
    card.idesp = b"AAA000001".to_vec();
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = open(card, &ui).unwrap();
    assert_eq!(s.info().cwa_set, CwaSet::R1);
    s.sign(CERT_AUTENTICACION, DigestAlgorithm::Sha1, b"r1", &ui).unwrap();
    let cmds: Vec<String> = inner_commands(s.transport())
        .iter()
        .map(|(_, c)| hex::encode_upper(c))
        .collect();
    assert!(cmds.iter().any(|c| c.contains("4000000000000001")));
    assert!(cmds.iter().any(|c| c.contains("2000000000000001")));
    assert!(cmds.iter().any(|c| c == "002241B60484020101"));
}

#[test]
fn wrong_can() {
    let ui = Recorder::new("654321", &[PIN]);
    let e = open(sim(4), &ui).err().unwrap();
    assert_eq!(e, DnieError::WrongCan { sw: Some(0x6300) });
    assert_category(&e, ErrorCategory::WrongCan);
    let ui = Recorder::new("12a", &[PIN]);
    let card = sim(4);
    let e = open(card, &ui).err().unwrap();
    assert_eq!(e, DnieError::InvalidCanFormat);
    // Cancelación del CAN.
    let mut ui = Recorder::new(CAN, &[PIN]);
    ui.can = None;
    assert_eq!(open(sim(4), &ui).err(), Some(DnieError::Cancelled));
}

#[test]
fn wrong_pin_retries_and_recovery() {
    let ui = Recorder::new(CAN, &["0000wxyz", "1111wxyz", PIN]);
    let mut s = open(sim(5), &ui).unwrap();
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui)
        .unwrap_err();
    assert_eq!(e, DnieError::WrongPin { retries_left: Some(2) });
    assert_category(&e, ErrorCategory::WrongPin);
    assert_eq!(s.transport().retries, 2);
    // Tras el error se descarta el canal (no se reutiliza el canal de PIN, quirk de §8.3).
    assert_eq!(s.context_name(), "sin SM");
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui)
        .unwrap_err();
    assert_eq!(e, DnieError::WrongPin { retries_left: Some(1) });
    // El PIN correcto restablece los intentos.
    s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui).unwrap();
    assert_eq!(s.transport().retries, 3);
    let p = ui.prompts();
    assert!(p[0].ends_with("Intentos restantes: 3"));
    assert!(p[1].ends_with("Intentos restantes: 2"));
    assert!(p[2].ends_with("Intentos restantes: 1"));
    // Un PIN con formato inválido no llega a la tarjeta.
    let ui2 = Recorder::new(CAN, &["pin ñ"]);
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui2)
        .unwrap_err();
    assert!(matches!(e, DnieError::InvalidPinFormat(_)));
    assert_eq!(s.transport().retries, 3);
}

#[test]
fn blocked_pin() {
    // Tres PIN erróneos: el último bloquea.
    let ui = Recorder::new(CAN, &["00000000"]);
    let mut s = open(sim(6), &ui).unwrap();
    for left in [2u8, 1] {
        let e = s
            .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui)
            .unwrap_err();
        assert_eq!(
            e,
            DnieError::WrongPin {
                retries_left: Some(left)
            }
        );
    }
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui)
        .unwrap_err();
    assert_eq!(e, DnieError::PinBlocked);
    assert_category(&e, ErrorCategory::PinBlocked);
    // Ya bloqueado: se detecta con la consulta de intentos, sin pedir PIN ni enviar VERIFY.
    let before = ui.prompts().len();
    let verifies_before = count_verifies(s.transport());
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui)
        .unwrap_err();
    assert_eq!(e, DnieError::PinBlocked);
    assert_eq!(ui.prompts().len(), before);
    assert_eq!(count_verifies(s.transport()), verifies_before);
}

fn count_verifies(card: &SimCard) -> usize {
    card.transcript()
        .iter()
        .filter(|t| t.inner.as_ref().is_some_and(|i| i.len() > 5 && i[1] == 0x20))
        .count()
}

#[test]
fn card_removed_mid_session() {
    // Retirada durante la carga.
    let mut card = sim(7);
    card.faults.remove_at_apdu = Some(20);
    let ui = Recorder::new(CAN, &[PIN]);
    let e = open(card, &ui).err().unwrap();
    assert!(matches!(e, DnieError::Transport(TransportError::TagLost(_))), "{e:?}");
    assert_category(&e, ErrorCategory::ReadError);

    // Retirada durante la firma (handshake del canal de usuario): se intenta reabrir una vez
    // desde PACE, falla igual y se informa de la pérdida del enlace.
    let mut s = open(sim(8), &ui).unwrap();
    s.transport_mut().faults.remove_at_apdu = Some(56 + 20);
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui)
        .unwrap_err();
    assert!(matches!(e, DnieError::Transport(TransportError::TagLost(_))), "{e:?}");
    // Al volver a acercarla, la siguiente firma empieza desde PACE y funciona.
    s.transport_mut().reinsert();
    s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui).unwrap();
}

#[test]
fn sm_loss_reopens_from_pace_once() {
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = open(sim(9), &ui).unwrap();
    // 6987 inesperado en el handshake del canal de PIN: se reabre desde PACE y se firma.
    s.transport_mut().faults.drop_sm_at_apdu = Some(56 + 4);
    s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui).unwrap();
    assert_eq!(s.transport().stats.pace_sessions, 2);
    // MAC alterado en una respuesta del canal de usuario tras VERIFY correcto: se reabre y se
    // reutiliza el PIN ya verificado.
    let n = s.apdu_count();
    s.transport_mut().faults.corrupt_mac_at_apdu = Some(n + 5 + 20);
    s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"b", &ui).unwrap();
    assert_eq!(ui.prompts().len(), 2, "el PIN se pide una vez por firma");
    // 6987 justo en el VERIFY: resultado desconocido → no se reintenta.
    let n = s.apdu_count();
    let verify_at = n + 5 + 17;
    s.transport_mut().faults.drop_sm_at_apdu = Some(verify_at);
    let e = s
        .sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"c", &ui)
        .unwrap_err();
    assert!(matches!(e, DnieError::SecureMessaging(_)), "{e:?}");
    let verify_cmd = &s.transport().transcript()[verify_at - 1];
    assert_eq!(verify_cmd.command[1], 0x20);
    assert_eq!(s.transport().retries, 3);
    // Y con la reapertura desactivada, un error de enlace se propaga sin reintentar.
    let card = sim(10);
    let mut s = DnieSession::open_with(
        card,
        &ui,
        Box::new(OsRandom),
        SessionOptions {
            reopen_on_link_error: false,
            ..Default::default()
        },
    )
    .unwrap();
    s.transport_mut().faults.drop_sm_at_apdu = Some(56 + 4);
    assert!(s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui).is_err());
}

#[test]
fn chunked_responses_and_outer_sw() {
    // Lector que trocea respuestas largas con 61xx (la de la firma mide 285 octetos).
    let mut card = sim(11);
    card.max_response_data = Some(200);
    card.cwa_outer_sw_equals_inner = true;
    let ui = Recorder::new(CAN, &[PIN]);
    let mut s = open(card, &ui).unwrap();
    s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha384, b"a", &ui).unwrap();
    let t = s.transport().transcript();
    assert!(t.iter().any(|e| e.command == hex::decode("00C0000053").unwrap()));
    assert!(t.iter().all(|e| e.response.len() <= 202));
    assert!(ui.prompts()[0].ends_with("Intentos restantes: 3"));
}

#[test]
fn detection_and_unsupported_cards() {
    let ui = Recorder::new(CAN, &[PIN]);
    // CERES por PC/SC: rechazada sin enviar ninguna APDU.
    let mut card = sim(12);
    card.identification =
        CardIdentification::from_atr(hex::decode("3B8F8001804F0CA000000306030001000000006A").unwrap());
    let e = DnieSession::open(card, &ui).err().unwrap();
    assert_category(&e, ErrorCategory::CardNotSupported);
    // Android: tipo B con datos de aplicación del DNIe → aceptada; otros datos → rechazada.
    let mut card = sim(13);
    card.identification = CardIdentification {
        hi_layer_response: Some(vec![]),
        nfcb_application_data: Some(hex::decode("E1F35E11").unwrap()),
        nfcb_protocol_info: Some(hex::decode("7781A1").unwrap()),
        ..Default::default()
    };
    let s = DnieSession::open(card, &ui).unwrap();
    assert!(matches!(s.info().evidence, DetectionEvidence::NfcBPseudoAtr(_)));
    let mut card = sim(14);
    card.identification = CardIdentification {
        hi_layer_response: Some(vec![]),
        nfcb_application_data: Some(hex::decode("00000000").unwrap()),
        nfcb_protocol_info: Some(hex::decode("7781A1").unwrap()),
        ..Default::default()
    };
    let e = DnieSession::open(card, &ui).err().unwrap();
    assert_category(&e, ErrorCategory::CardNotSupported);
    // Paridad JMulticard: HLR vacío sin datos del ATQB se acepta.
    let mut card = sim(15);
    card.identification = CardIdentification {
        hi_layer_response: Some(vec![]),
        ..Default::default()
    };
    let s = DnieSession::open(card, &ui).unwrap();
    assert!(matches!(s.info().evidence, DetectionEvidence::ResetBytes(_)));
    // «TIE»: se detecta como DNIe (mismo pseudo-ATR) pero no tiene la estructura del DNIe.
    let mut card = sim(16);
    card.identification = CardIdentification::from_atr(hex::decode("3B8C800150D71A03F3E1F35E117781A16A").unwrap());
    assert!(card.remove_file([0x50, 0x15], [0x60, 0x04]));
    let e = DnieSession::open(card, &ui).err().unwrap();
    assert_category(&e, ErrorCategory::CardNotSupported);
    // Política JMulticard explícita sobre el mismo HLR vacío.
    let mut card = sim(17);
    card.identification = CardIdentification::default();
    let opts = SessionOptions {
        detection: DetectionPolicy::JMulticard,
        ..Default::default()
    };
    assert!(DnieSession::open_with(card, &ui, Box::new(OsRandom), opts).is_ok());
}

#[test]
fn unknown_alias_and_unsupported_digest() {
    let ui = FixedInteraction::new(Some(CAN), Some(PIN));
    let mut s = DnieSession::open(sim(18), &ui).unwrap();
    let e = s
        .sign("CertCAIntermediaDGP", DigestAlgorithm::Sha256, b"a", &ui)
        .unwrap_err();
    assert_eq!(e, DnieError::AliasNotFound("CertCAIntermediaDGP".into()));
    assert!(
        s.sign_digest(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, &[0; 20], &ui)
            .is_err()
    );
    // Confirmación rechazada.
    let mut ui = Recorder::new(CAN, &[PIN]);
    ui.confirm = false;
    assert_eq!(
        s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui).err(),
        Some(DnieError::Cancelled)
    );
    // PIN cancelado.
    let ui = FixedInteraction::new(Some(CAN), None);
    assert_eq!(
        s.sign(CERT_FIRMA_DIGITAL, DigestAlgorithm::Sha256, b"a", &ui).err(),
        Some(DnieError::Cancelled)
    );
    // Recarga (botón «Recargar»): vuelve a PACE y a leer certificados.
    s.reload().unwrap();
    assert_eq!(s.keys().len(), 2);
    let card = s.close();
    assert_eq!(card.context_name(), "sin SM");
}
