use chrono::{TimeZone, Utc};

use super::*;

#[test]
fn oid_roundtrip() {
    for s in [
        "1.2.840.113549.1.7.2",
        "2.16.724.1.3.1.1.2.1.9",
        "2.5.4.3",
        "1.3.6.1.4.1.311.60.2.1.3",
        "2.999.3",
    ] {
        let o = Oid::new(s);
        assert_eq!(o.to_dotted(), s);
        let der = der::oid(&o);
        let (tlv, rest) = Tlv::parse(&der).unwrap();
        assert!(rest.is_empty());
        assert_eq!(tlv.as_oid().unwrap(), o);
    }
    assert_eq!(
        der::oid_str("1.2.840.113549.1.7.2"),
        hex::decode("06092a864886f70d010702").unwrap()
    );
}

#[test]
fn integers() {
    assert_eq!(der::integer_i64(0), [2, 1, 0]);
    assert_eq!(der::integer_i64(127), [2, 1, 0x7f]);
    assert_eq!(der::integer_i64(128), [2, 2, 0, 0x80]);
    assert_eq!(der::integer_i64(-1), [2, 1, 0xff]);
    assert_eq!(der::integer_i64(-129), [2, 2, 0xff, 0x7f]);
    assert_eq!(der::integer_unsigned(&[0, 0, 0x80]), [2, 2, 0, 0x80]);
    for v in [0i64, 1, -1, 300, -300, i64::MAX, i64::MIN] {
        let enc = der::integer_i64(v);
        assert_eq!(Tlv::parse_single(&enc).unwrap().as_i64().unwrap(), v);
    }
}

#[test]
fn long_lengths() {
    let content = vec![0xab; 300];
    let enc = der::octet_string(&content);
    assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2c]);
    let t = Tlv::parse_single(&enc).unwrap();
    assert_eq!(t.value, &content[..]);
}

#[test]
fn ber_indefinite_and_constructed_octets() {
    // SEQUENCE (indef) { OCTET STRING constructed (indef) { "ab", "cd" } }
    let ber = hex::decode("3080248004026162040263640000".to_owned() + "0000").unwrap();
    let t = Tlv::parse_single(&ber).unwrap();
    assert!(t.indefinite);
    let kids = t.children().unwrap();
    assert_eq!(kids.len(), 1);
    assert_eq!(kids[0].octet_string_content().unwrap(), b"abcd");
    let def = t.to_definite();
    let t2 = Tlv::parse_single(&def).unwrap();
    assert!(!t2.indefinite);
    assert_eq!(t2.children().unwrap()[0].octet_string_content().unwrap(), b"abcd");
}

#[test]
fn set_of_is_sorted() {
    let a = der::integer_i64(5);
    let b = der::integer_i64(1);
    let s = der::set_of([a.clone(), b.clone()]);
    assert_eq!(s, [0x31, 6, 2, 1, 1, 2, 1, 5]);
}

#[test]
fn times() {
    let t = Utc.with_ymd_and_hms(2024, 3, 5, 7, 8, 9).unwrap();
    let u = der::utc_time(&t);
    assert_eq!(&u[2..], b"240305070809Z");
    assert_eq!(Tlv::parse_single(&u).unwrap().as_time().unwrap(), t);
    let g = der::generalized_time(&t, false);
    assert_eq!(&g[2..], b"20240305070809Z");
    assert_eq!(Tlv::parse_single(&g).unwrap().as_time().unwrap(), t);
    let enc = der::tlv(tags::GENERALIZED_TIME, b"20240305080809.25+0100");
    let gt = Tlv::parse_single(&enc).unwrap();
    assert_eq!(gt.as_time().unwrap(), t + chrono::Duration::milliseconds(250));
}

#[test]
fn high_tag_numbers() {
    let tag = Tag::context(200, true);
    let enc = der::tlv(tag, &[]);
    let t = Tlv::parse_single(&enc).unwrap();
    assert_eq!(t.tag, tag);
}

#[test]
fn rejects_truncated() {
    assert_eq!(Tlv::parse(&[0x30, 0x05, 0x01]).unwrap_err(), Asn1Error::Truncated);
    assert!(Tlv::parse(&[0x30, 0x80, 0x02, 0x01]).is_err());
}
