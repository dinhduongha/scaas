// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! LEGACY (not compiled): `PayMeta` v2 of `scaas_ua::pay` as it stood at b73b3a6a (pay-meta-tax T41): `payNo` a string of at
//! most 256 bytes with the UTF-8 / control / bidi rules, the commitment under `scaas.pay.meta.v2`. `ua-mtx-merge` T83 (owner
//! 2026-11-09) made `payNo` a `bytes32`, added `save` and the tag `scaas.pay.meta.v3`; ua-rs-sign T20e1 took it. The v2 rows
//! are `smartcontracts/vectors/metatx/legacy/ua-mtx-merge/t83/paymeta.json`. Kept for reference, never deleted.

pub const PAY_NO_MAX: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayError {
    /// `salt == 0`, or `schema == 0` and a body, or a schema above 0 and none (`PayMetaShape`).
    Shape,
    /// `payNo` over 256 bytes (`PayNoTooLong`).
    PayNoTooLong,
    /// A control character or a bidirectional mark, embedding, override or isolate in `payNo` (display spoofing).
    PayNoText,
    /// `taxMode` not 1 (PERCENT) or 2 (AMOUNT), or `tax > value`.
    Tax,
}

/// `PayMeta {salt, payNo, schema, body}`, the last parameter of every pay entry (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayMeta {
    pub salt: [u8; 32],
    pub pay_no: String,
    pub schema: u16,
    pub body: Vec<u8>,
}

/// A `payNo` a wallet signs (spec §3.1): at most 256 bytes of UTF-8 (a Rust `str` is valid UTF-8), no C0 / C1 control
/// or DEL, no bidirectional mark, embedding, override or isolate (U+061C, U+200E, U+200F, U+202A-202E, U+2066-2069).
pub fn check_pay_no(pay_no: &str) -> Result<(), PayError> {
    if pay_no.len() > PAY_NO_MAX {
        return Err(PayError::PayNoTooLong);
    }
    let bad = |c: char| c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    if pay_no.chars().any(bad) {
        return Err(PayError::PayNoText);
    }
    Ok(())
}

fn padded(b: &[u8]) -> Vec<u8> {
    let mut v = word(b.len() as u64).to_vec();
    v.extend_from_slice(b);
    v.resize(32 + b.len().div_ceil(32) * 32, 0);
    v
}

/// `metaPayId(m) = keccak256("scaas.pay.meta.v2" ‖ salt ‖ keccak256(abi.encode(string payNo, uint16 schema, bytes body)))`
/// (CTR-MTX-26 Change), after the shape and `payNo` checks of `_payMeta` and the wallet rules.
pub fn meta_pay_id_v2(m: &PayMeta) -> Result<[u8; 32], PayError> {
    if m.salt == [0; 32] || (m.schema == 0) != m.body.is_empty() {
        return Err(PayError::Shape);
    }
    check_pay_no(&m.pay_no)?;
    let (no, body) = (padded(m.pay_no.as_bytes()), padded(&m.body));
    let mut enc = word(0x60).to_vec();
    enc.extend_from_slice(&word(m.schema as u64));
    enc.extend_from_slice(&word(0x60 + no.len() as u64));
    enc.extend(no);
    enc.extend(body);
    Ok(keccak(&[b"scaas.pay.meta.v2", &m.salt, &keccak256(&enc)]))
}

// tests/pay.rs at b73b3a6a: the v2 rows and the payNo text rules
#[test]
fn paymeta_v2_rows() {
    let rows = load("metatx/legacy/ua-mtx-merge/t83/paymeta.json");
    assert_eq!(rows.as_array().unwrap().len(), 9);
    for r in rows.as_array().unwrap() {
        let m = PayMeta { salt: b32(&r["salt"]), pay_no: r["payNo"].as_str().unwrap().into(),
            schema: r["schema"].as_u64().unwrap() as u16, body: bytes(&r["body"]) };
        if r["accepted"].as_bool().unwrap() {
            assert_eq!(meta_pay_id_v2(&m).unwrap(), b32(&r["payId"]), "{}", r["name"]);
        } else {
            assert_eq!(meta_pay_id_v2(&m), Err(PayError::PayNoTooLong), "{}", r["name"]);
        }
    }
}

#[test]
fn pay_meta_shape_and_pay_no_text() {
    let m = |salt: u8, schema: u16, body: &[u8]| PayMeta { salt: [salt; 32], pay_no: String::new(), schema, body: body.to_vec() };
    assert_eq!(meta_pay_id_v2(&m(0, 0, b"")), Err(PayError::Shape));
    assert_eq!(meta_pay_id_v2(&m(1, 0, b"x")), Err(PayError::Shape));
    assert_eq!(meta_pay_id_v2(&m(1, 1, b"")), Err(PayError::Shape));
    assert!(meta_pay_id_v2(&m(1, 1, b"x")).is_ok());
    assert_eq!(check_pay_no(&"A".repeat(256)), Ok(()));
    assert_eq!(check_pay_no(&"A".repeat(257)), Err(PayError::PayNoTooLong));
    for bad in ["INV\u{202e}1", "INV\u{2066}x\u{2069}", "INV\n1", "INV\u{85}", "a\u{200f}b", "x\u{61c}"] {
        assert_eq!(check_pay_no(bad), Err(PayError::PayNoText), "{bad:?}");
    }
}
