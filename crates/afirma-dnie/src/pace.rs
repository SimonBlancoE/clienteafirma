//! PACE con CAN: `id-PACE-ECDH-GM-AES-CBC-CMAC-128` sobre brainpoolP256r1 (ICAO 9303-11,
//! BSI TR-03110; especificación 10 §4).
//!
//! Secuencia (todas las APDU en claro y sin Le, como JMulticard):
//! `MSE:SET AT` → GA1 «nonce cifrado» → GA2 «mapeo» → GA3 «acuerdo de claves» → GA4
//! «autenticación mutua». Se corrigen los defectos de JMulticard: la coordenada X del secreto
//! compartido se codifica siempre con 32 octetos (P1, el fallo de ~1/170 sesiones), se verifica el
//! token de la tarjeta `T_ICC` (P2), se validan los puntos recibidos y `PK_ICC ≠ PK_IFD` (P3), las
//! claves efímeras son uniformes en `[1, n−1]` (P4) y se comprueban las etiquetas (P5).

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use crate::apdu::{CommandApdu, ResponseApdu, sw};
use crate::crypto::{self, Key16};
use crate::ec::{Point, Scalar};
use crate::error::DnieError;
use crate::rng::RandomSource;
use crate::sm::PaceSm;
use crate::tlv;

/// OID `id-PACE-ECDH-GM-AES-CBC-CMAC-128` (0.4.0.127.0.7.2.2.4.2.2), sin etiqueta ni longitud.
pub const PACE_OID: [u8; 10] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02];
/// Parámetro de dominio estandarizado 13 (brainpoolP256r1).
pub const DOMAIN_PARAMETER_ID: u8 = 0x0D;

/// Contraseña PACE.
#[derive(Clone)]
pub enum PacePassword {
    /// CAN (6 dígitos impresos en el anverso del DNIe; referencia `02`).
    Can(Zeroizing<String>),
    /// Clave derivada de la MRZ, `SHA-1(número ‖ cd ‖ nacimiento ‖ cd ‖ caducidad ‖ cd)`
    /// (referencia `01`). JMulticard la admite; la app no la usa.
    Mrz(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for PacePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacePassword::Can(_) => f.write_str("PacePassword::Can(***)"),
            PacePassword::Mrz(_) => f.write_str("PacePassword::Mrz(***)"),
        }
    }
}

impl PacePassword {
    /// CAN de 1 a 6 dígitos ASCII (JMulticard acepta hasta 6; la app exige exactamente 6).
    pub fn can(can: &str) -> Result<PacePassword, DnieError> {
        if can.is_empty() || can.len() > 6 || !can.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DnieError::InvalidCanFormat);
        }
        Ok(PacePassword::Can(Zeroizing::new(can.to_string())))
    }

    /// Contraseña MRZ a partir de la cadena `MRZ_info` ya formada (número de documento,
    /// fecha de nacimiento y de caducidad, cada uno con su dígito de control).
    pub fn mrz_info(mrz_info: &str) -> PacePassword {
        PacePassword::Mrz(Zeroizing::new(Sha1::digest(mrz_info.as_bytes()).to_vec()))
    }

    /// Referencia de la contraseña en `MSE:SET AT` (`83 01 xx`).
    pub fn reference(&self) -> u8 {
        match self {
            PacePassword::Can(_) => 0x02,
            PacePassword::Mrz(_) => 0x01,
        }
    }

    /// `π` tal como entra en la KDF.
    fn secret(&self) -> &[u8] {
        match self {
            PacePassword::Can(s) => s.as_bytes(),
            PacePassword::Mrz(k) => k,
        }
    }

    /// `K_π = SHA-1(π ‖ 00000003)[0..16]`.
    pub fn key(&self) -> Key16 {
        crypto::kdf_sha1(self.secret(), 3)
    }
}

/// `MSE:SET AT` de PACE (§4.3 paso 1).
pub fn mse_set_at(password_ref: u8) -> CommandApdu {
    let mut data = vec![0x80, PACE_OID.len() as u8];
    data.extend_from_slice(&PACE_OID);
    data.extend_from_slice(&[0x83, 0x01, password_ref, 0x84, 0x01, DOMAIN_PARAMETER_ID]);
    CommandApdu::new(0x00, 0x22, 0xC1, 0xA4).with_data(data)
}

/// GENERAL AUTHENTICATE con un objeto de datos dinámicos de autenticación (`7C`).
fn general_authenticate(chained: bool, inner_tag: u8, value: &[u8]) -> CommandApdu {
    let inner = if inner_tag == 0 {
        Vec::new()
    } else {
        tlv::encode(inner_tag as u16, value)
    };
    CommandApdu::new(if chained { 0x10 } else { 0x00 }, 0x86, 0x00, 0x00).with_data(tlv::encode(0x7C, &inner))
}

/// Extrae el valor del objeto `expected` dentro de `7C` (comprobando ambas etiquetas, P5).
fn dyn_auth_value(resp: &ResponseApdu, expected: u8) -> Result<&[u8], DnieError> {
    let bad = || {
        DnieError::SecureMessaging(format!(
            "Respuesta de GENERAL AUTHENTICATE mal formada (se esperaba 7C/{expected:02X}): {}",
            hex::encode_upper(&resp.data)
        ))
    };
    let (outer, used) = tlv::parse_one(&resp.data).map_err(|_| bad())?;
    if outer.tag != 0x7C || used != resp.data.len() {
        return Err(bad());
    }
    let (inner, used) = tlv::parse_one(outer.value).map_err(|_| bad())?;
    if inner.tag != expected as u32 || used != outer.value.len() {
        return Err(bad());
    }
    Ok(inner.value)
}

/// Entrada del token de autenticación: `7F49 4F 06 0A OID 86 41 ‖ PK(65)`.
pub fn auth_token_input(pk: &Point) -> Vec<u8> {
    let mut oid = vec![0x06, PACE_OID.len() as u8];
    oid.extend_from_slice(&PACE_OID);
    let mut body = oid;
    body.extend_from_slice(&tlv::encode(0x86, &pk.to_uncompressed()));
    tlv::encode(0x7F49, &body)
}

/// Token de autenticación `T = CMAC(K_mac, entrada(PK))[0..8]`.
pub fn auth_token(kmac: &[u8; 16], pk: &Point) -> [u8; 8] {
    crypto::aes_cmac8(kmac, &auth_token_input(pk))
}

/// Descifra el nonce: `s = AES-CBC⁻¹(K_π, IV = 0, z)`.
pub fn decrypt_nonce(password: &PacePassword, z: &[u8]) -> Result<Zeroizing<Vec<u8>>, DnieError> {
    if z.is_empty() || !z.len().is_multiple_of(16) {
        return Err(DnieError::SecureMessaging(format!(
            "Nonce PACE cifrado de {} octetos",
            z.len()
        )));
    }
    crypto::aes_cbc_decrypt(&password.key(), &[0u8; 16], z)
}

/// Generador mapeado `G' = s·G + H` (mapeo genérico).
pub fn map_generator(s: &[u8], h: &Point) -> Result<Point, DnieError> {
    let s = Scalar::from_be_bytes(s)?;
    let sg = Point::generator()
        .mul(&s)
        .ok_or_else(|| DnieError::SecureMessaging("Nonce PACE nulo".into()))?;
    sg.add(h)
        .ok_or_else(|| DnieError::SecureMessaging("Generador PACE mapeado a la identidad".into()))
}

/// Claves de sesión a partir de la coordenada X del secreto compartido (32 octetos fijos).
pub fn session_keys(shared_x: &[u8; 32]) -> (Key16, Key16) {
    (crypto::kdf_sha1(shared_x, 1), crypto::kdf_sha1(shared_x, 2))
}

/// Resultado de PACE.
pub struct PaceOutcome {
    /// Contexto de mensajería segura recién negociado (SSC = 0).
    pub sm: PaceSm,
}

/// Ejecuta PACE. `tx` envía un comando en claro y devuelve la respuesta.
pub fn establish(
    tx: &mut dyn FnMut(&CommandApdu) -> Result<ResponseApdu, DnieError>,
    password: &PacePassword,
    rng: &mut dyn RandomSource,
) -> Result<PaceOutcome, DnieError> {
    // Paso 1: MSE:SET AT.
    let r = tx(&mse_set_at(password.reference()))?;
    if !r.is_ok() {
        return Err(DnieError::CardNotSupported(format!(
            "la tarjeta no admite PACE con brainpoolP256r1 (respuesta {:04X} a MSE:SET AT)",
            r.sw
        )));
    }

    // Paso 2: nonce cifrado.
    let r = tx(&general_authenticate(true, 0, &[]))?;
    if !r.is_ok() {
        return Err(DnieError::card("PACE: petición del nonce", r.sw));
    }
    let s = decrypt_nonce(password, dyn_auth_value(&r, 0x80)?)?;

    // Paso 3: mapeo.
    let sk_map = Scalar::random(rng)?;
    let pk_map = Point::generator()
        .mul(&sk_map)
        .ok_or_else(|| DnieError::SecureMessaging("Clave de mapeo nula".into()))?;
    let r = tx(&general_authenticate(true, 0x81, &pk_map.to_uncompressed()))?;
    if !r.is_ok() {
        return Err(DnieError::card("PACE: mapeo del nonce", r.sw));
    }
    let pk_map_icc = Point::from_uncompressed(dyn_auth_value(&r, 0x82)?)?;
    if pk_map_icc == pk_map {
        return Err(DnieError::SecureMessaging(
            "La tarjeta ha devuelto la misma clave de mapeo".into(),
        ));
    }
    let h = pk_map_icc
        .mul(&sk_map)
        .ok_or_else(|| DnieError::SecureMessaging("Punto H de PACE nulo".into()))?;
    drop(sk_map);
    let g_mapped = map_generator(&s, &h)?;
    drop(s);

    // Paso 4: acuerdo de claves.
    let sk = Scalar::random(rng)?;
    let pk_ifd = g_mapped
        .mul(&sk)
        .ok_or_else(|| DnieError::SecureMessaging("Clave efímera nula".into()))?;
    let r = tx(&general_authenticate(true, 0x83, &pk_ifd.to_uncompressed()))?;
    if !r.is_ok() {
        return Err(DnieError::card("PACE: acuerdo de claves", r.sw));
    }
    let pk_icc = Point::from_uncompressed(dyn_auth_value(&r, 0x84)?)?;
    if pk_icc == pk_ifd {
        return Err(DnieError::SecureMessaging(
            "La clave efímera de la tarjeta coincide con la del terminal".into(),
        ));
    }
    let shared = pk_icc
        .mul(&sk)
        .ok_or_else(|| DnieError::SecureMessaging("Secreto compartido PACE nulo".into()))?;
    drop(sk);
    let kx = Zeroizing::new(shared.x_bytes());
    let (kenc, kmac) = session_keys(&kx);

    // Paso 5: autenticación mutua (CLA 00: fin del encadenamiento).
    let t_ifd = auth_token(&kmac, &pk_icc);
    let r = tx(&general_authenticate(false, 0x85, &t_ifd))?;
    if r.sw != sw::OK {
        return Err(DnieError::WrongCan { sw: Some(r.sw) });
    }
    let t_icc = dyn_auth_value(&r, 0x86)?;
    if !crypto::ct_eq(t_icc, &auth_token(&kmac, &pk_ifd)) {
        return Err(DnieError::SecureMessaging(
            "La tarjeta no se ha autenticado: token PACE (T_ICC) incorrecto".into(),
        ));
    }
    Ok(PaceOutcome {
        sm: PaceSm::new(kenc, kmac),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::ScriptedRandom;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '\n'], "")).unwrap()
    }

    fn pt(x: &str, y: &str) -> Point {
        Point::from_uncompressed(&[vec![4], hx(x), hx(y)].concat()).unwrap()
    }

    fn sc(s: &str) -> Scalar {
        Scalar::from_be_bytes(&hx(s)).unwrap()
    }

    const SK_MAP_IFD: &str = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
    const SK_MAP_ICC: &str = "498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560";
    const SK_IFD: &str = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";
    const SK_ICC: &str = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";

    /// Ejemplo trabajado de ICAO 9303-11 (PACE – Generic Mapping, ECDH), §4.5: todos los
    /// valores intermedios.
    #[test]
    fn icao_worked_example_every_value() {
        let pwd = PacePassword::mrz_info("T22000129364081251010318");
        let PacePassword::Mrz(k) = &pwd else { unreachable!() };
        assert_eq!(k.to_vec(), hx("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD"));
        assert_eq!(pwd.reference(), 1);
        assert_eq!(pwd.key().to_vec(), hx("89DED1B26624EC1E634C1989302849DD"));
        let s = decrypt_nonce(&pwd, &hx("95A3A016522EE98D01E76CB6B98B42C3")).unwrap();
        assert_eq!(s.to_vec(), hx("3F00C4D39D153F2B2A214A078D899B22"));

        let g = Point::generator();
        let pk_map_ifd = g.mul(&sc(SK_MAP_IFD)).unwrap();
        assert_eq!(
            pk_map_ifd,
            pt(
                "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E",
                "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D"
            )
        );
        let pk_map_icc = g.mul(&sc(SK_MAP_ICC)).unwrap();
        assert_eq!(
            pk_map_icc,
            pt(
                "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57",
                "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54"
            )
        );
        let h = pk_map_icc.mul(&sc(SK_MAP_IFD)).unwrap();
        assert_eq!(h, pk_map_ifd.mul(&sc(SK_MAP_ICC)).unwrap());
        assert_eq!(
            h,
            pt(
                "60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5",
                "0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181"
            )
        );
        let gm = map_generator(&s, &h).unwrap();
        assert_eq!(
            gm,
            pt(
                "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2",
                "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522"
            )
        );
        let pk_ifd = gm.mul(&sc(SK_IFD)).unwrap();
        assert_eq!(
            pk_ifd,
            pt(
                "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C",
                "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462"
            )
        );
        let pk_icc = gm.mul(&sc(SK_ICC)).unwrap();
        assert_eq!(
            pk_icc,
            pt(
                "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB",
                "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094"
            )
        );
        let k = pk_icc.mul(&sc(SK_IFD)).unwrap();
        assert_eq!(k, pk_ifd.mul(&sc(SK_ICC)).unwrap());
        assert_eq!(
            k.x_bytes().to_vec(),
            hx("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925")
        );
        let (kenc, kmac) = session_keys(&k.x_bytes());
        assert_eq!(kenc.to_vec(), hx("F5F0E35C0D7161EE6724EE513A0D9A7F"));
        assert_eq!(kmac.to_vec(), hx("FE251C7858B356B24514B3BD5F4297D1"));
        assert_eq!(
            auth_token_input(&pk_icc)[..19].to_vec(),
            hx("7F494F060A04007F00070202040202864104")
                .into_iter()
                .chain([0x9E])
                .collect::<Vec<_>>()
        );
        assert_eq!(auth_token(&kmac, &pk_icc).to_vec(), hx("C2B0BD78D94BA866"));
        assert_eq!(auth_token(&kmac, &pk_ifd).to_vec(), hx("3ABB9674BCE93C08"));
    }

    /// Tarjeta guionizada que reproduce §4.6 y comprueba cada APDU enviada.
    fn scripted_card(
        steps: Vec<(&'static str, &'static str)>,
    ) -> impl FnMut(&CommandApdu) -> Result<ResponseApdu, DnieError> {
        let mut steps = steps.into_iter();
        move |cmd: &CommandApdu| {
            let (exp, resp) = steps.next().expect("APDU de más");
            assert_eq!(hex::encode_upper(cmd.encode()), exp.replace([' ', '\n'], ""));
            ResponseApdu::parse(&hx(resp))
        }
    }

    const GA2: &str = "10860000457C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E\
                       544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D";
    const GA2R: &str = "7C43824104824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57\
                        30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54 9000";
    const GA3: &str = "10860000457C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C\
                       3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462";
    const GA3R: &str = "7C438441049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB\
                        7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094 9000";

    fn vector_rng() -> ScriptedRandom {
        ScriptedRandom::new([hx(SK_MAP_IFD), hx(SK_IFD)])
    }

    #[test]
    fn can_vector_jmulticard_format() {
        // §4.6: mismas claves efímeras que ICAO con CAN = "123456"; APDU exactamente como
        // JMulticard (CLA 10 en GA1–GA3, sin Le, `84 01 0D`).
        let pwd = PacePassword::can("123456").unwrap();
        assert_eq!(pwd.key().to_vec(), hx("591468CDA83D65219CCCB8560233600F"));
        let mut card = scripted_card(vec![
            ("0022C1A412800A04007F0007020204020283010284010D", "9000"),
            ("10860000027C00", "7C12801084EBAB7F2DE981C6FA6922A691AE0911 9000"),
            (GA2, GA2R),
            (GA3, GA3R),
            ("008600000C7C0A8508C2B0BD78D94BA866", "7C0A86083ABB9674BCE93C08 9000"),
        ]);
        let out = establish(&mut card, &pwd, &mut vector_rng()).unwrap();
        // El contexto resultante es el de §5.4 b (misma primera APDU protegida).
        let mut sm = out.sm;
        assert_eq!(
            sm.wrap(&CommandApdu::new(0, 0xA4, 4, 0).with_data(b"Master.File".to_vec()))
                .unwrap(),
            hx("0CA404001D8711011D75C8363A14ACA516C1DE24B08357668E0847E2D5CE090F139600")
        );
    }

    #[test]
    fn wrong_can_and_bad_card_token() {
        let pwd = PacePassword::can("123456").unwrap();
        let mut card = scripted_card(vec![
            ("0022C1A412800A04007F0007020204020283010284010D", "9000"),
            ("10860000027C00", "7C12801084EBAB7F2DE981C6FA6922A691AE0911 9000"),
            (GA2, GA2R),
            (GA3, GA3R),
            ("008600000C7C0A8508C2B0BD78D94BA866", "6300"),
        ]);
        assert_eq!(
            establish(&mut card, &pwd, &mut vector_rng()).err(),
            Some(DnieError::WrongCan { sw: Some(0x6300) })
        );
        let mut card = scripted_card(vec![
            ("0022C1A412800A04007F0007020204020283010284010D", "9000"),
            ("10860000027C00", "7C12801084EBAB7F2DE981C6FA6922A691AE0911 9000"),
            (GA2, GA2R),
            (GA3, GA3R),
            ("008600000C7C0A8508C2B0BD78D94BA866", "7C0A86083ABB9674BCE93C09 9000"),
        ]);
        let e = establish(&mut card, &pwd, &mut vector_rng()).err().unwrap();
        assert!(
            matches!(e, DnieError::SecureMessaging(ref m) if m.contains("T_ICC")),
            "{e}"
        );
    }

    #[test]
    fn rejects_invalid_points_and_tags() {
        let pwd = PacePassword::can("123456").unwrap();
        // Punto de mapeo fuera de la curva (último octeto alterado).
        let mut bad = GA2R.replace(' ', "");
        bad.replace_range(bad.len() - 6..bad.len() - 4, "55");
        let bad: &'static str = Box::leak(bad.into_boxed_str());
        let mut card = scripted_card(vec![
            ("0022C1A412800A04007F0007020204020283010284010D", "9000"),
            ("10860000027C00", "7C12801084EBAB7F2DE981C6FA6922A691AE0911 9000"),
            (GA2, bad),
        ]);
        let e = establish(&mut card, &pwd, &mut vector_rng()).err().unwrap();
        assert!(e.to_string().contains("curva"), "{e}");
        // Etiqueta interna incorrecta en GA1.
        let mut card = scripted_card(vec![
            ("0022C1A412800A04007F0007020204020283010284010D", "9000"),
            ("10860000027C00", "7C12811084EBAB7F2DE981C6FA6922A691AE0911 9000"),
        ]);
        assert!(establish(&mut card, &pwd, &mut vector_rng()).is_err());
        // MSE:SET AT rechazado: no es un DNIe.
        let mut card = scripted_card(vec![("0022C1A412800A04007F0007020204020283010284010D", "6A80")]);
        assert!(matches!(
            establish(&mut card, &pwd, &mut vector_rng()),
            Err(DnieError::CardNotSupported(_))
        ));
    }

    #[test]
    fn can_format() {
        assert!(PacePassword::can("123456").is_ok());
        assert!(PacePassword::can("1").is_ok());
        assert_eq!(PacePassword::can("").err(), Some(DnieError::InvalidCanFormat));
        assert_eq!(PacePassword::can("1234567").err(), Some(DnieError::InvalidCanFormat));
        assert_eq!(PacePassword::can("12a456").err(), Some(DnieError::InvalidCanFormat));
        assert_eq!(PacePassword::can("123456").unwrap().reference(), 2);
    }

    #[test]
    fn fixed_length_shared_secret() {
        // Defecto P1: con X < 2^248 la clave se deriva de los 32 octetos (con el 00 inicial),
        // no de 31. Se busca un múltiplo de G cuya X empiece por 00.
        let g = Point::generator();
        let mut found = None;
        let mut p = g;
        for _ in 1u32..20000 {
            if p.x_bytes()[0] == 0 {
                found = Some(p);
                break;
            }
            p = p.add(&g).unwrap();
        }
        let p = found.expect("hay algún múltiplo pequeño con X = 00…");
        let x = p.x_bytes();
        let (kenc, _) = session_keys(&x);
        assert_eq!(kenc, crypto::kdf_sha1(&x, 1));
        assert_ne!(kenc, crypto::kdf_sha1(&x[1..], 1));
    }
}
