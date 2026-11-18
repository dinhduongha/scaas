// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Round 3t (CTR-PQZ-36): `scaas_ua::pqzfee` against the files clientkeys and the forge writer produce: the router's
//! `UASetVerifierFee` row of `typed/typed_ops.json` (type string, struct hash, digest; a non-zero unbound `relayer` and
//! `feeRecipient` hashed as 0, the row's mode 0) and the fee word of every row of `pqz/verifier_fee.json`.
use scaas_ua::pqzfee::{digest, pqz_fee_word, set_verifier_fee_struct_hash, set_verifier_fee_type};
use scaas_ua::regulated::{router_domain_separator, Envelope};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn b20(v: &Value) -> [u8; 20] {
    bytes(v).try_into().unwrap()
}
fn num(v: &Value) -> u128 {
    v.as_u64()
        .map(u128::from)
        .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
fn uint_word(v: &Value) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&num(v).to_be_bytes());
    w
}

#[test]
fn typed_ops_set_verifier_fee_row() {
    let v = load("typed/typed_ops.json");
    let r = &v["ops"]["UASetVerifierFee"];
    assert_eq!(set_verifier_fee_type(), r["typeString"].as_str().unwrap());
    let m = &r["message"];
    let d = &r["domains"]["gov_router"];
    let dom = &d["domain"];
    let ds = router_domain_separator(
        num(&dom["chainId"]) as u64,
        &b20(&dom["verifyingContract"]),
        &b32(&dom["salt"]),
    );
    let e = Envelope {
        from: b32(&m["from"]),
        batch: uint_word(&m["batch"]),
        nonce: uint_word(&m["nonce"]),
        valid_until: uint_word(&m["validUntil"]),
        mode: num(&m["mode"]) as u32,
        relayer: b20(&m["relayer"]),
        fee: uint_word(&m["fee"]),
        fee_recipient: b20(&m["feeRecipient"]),
    };
    assert_eq!(e.mode, 0, "relayer and fee recipient unbound");
    let (target, next, cu) = (
        b20(&m["target"]),
        num(&m["next"]) as u64,
        b32(&m["chainUid"]),
    );
    let sh = set_verifier_fee_struct_hash(&e, &target, next, &cu);
    assert_eq!(sh, b32(&r["structHash"]));
    assert_eq!(digest(&ds, &sh), b32(&d["digest"]));
    let junk = Envelope {
        relayer: [0xba; 20],
        fee_recipient: [0xba; 20],
        ..e
    };
    assert_eq!(
        digest(
            &ds,
            &set_verifier_fee_struct_hash(&junk, &target, next, &cu)
        ),
        b32(&d["digest"]),
        "unbound: hashed as 0"
    );
    assert_ne!(
        set_verifier_fee_struct_hash(&e, &target, next + 1, &cu),
        sh,
        "next bound"
    );
    assert_ne!(
        set_verifier_fee_struct_hash(&e, &target, next, &[0; 32]),
        sh,
        "the chain word bound (CTR-GOV-28)"
    );
}

#[test]
fn verifier_fee_rows() {
    let v = load("pqz/n2304-kmax4096/verifier_fee.json"); // T-05: in its set's directory
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len() as u128, num(&v["rowCount"]));
    for r in rows {
        let w = pqz_fee_word(
            num(&r["confidentialFee"]) as u64,
            r["beneficiary"].as_bool().unwrap(),
            num(&r["verifierFee"]) as u64,
            num(&r["legs"]) as u64,
            num(&r["decoyFee"]) as u64,
        )
        .unwrap();
        assert_eq!(w as u128, num(&r["feeWord"]), "{}", r["form"]);
        assert_eq!(
            num(&r["payVerifier"]),
            num(&r["verifierFee"]) * num(&r["shieldScale"]),
            "{}",
            r["form"]
        );
    }
    assert_eq!(pqz_fee_word(u64::MAX, true, 1, 0, 0), None, "2^64 refused");
}

/// T21 L77: `facade::pqz::bind_mode` against the forge writer's `binding` rows (`PqzCore._bindMode` on a direct op 1 and op 7,
/// word 544): `OFFCHAIN` at verifier fees 0, 1, 7 and 10 (`TAG_DIRECT_MODE_VF`, the fee hashed at 0 too) and `PRECOMPILE`, both
/// modes. A relayed binding is the envelope's on either verification (the contract's `binding == 0` branch only).
#[cfg(feature = "pqz")]
#[test]
fn bind_mode_rows() {
    use scaas_ua::facade::pqz::{bind_mode, Mode, Verification};
    let v = load("pqz/n2304-kmax4096/verifier_fee.json");
    let rows = v["binding"].as_array().unwrap();
    let offchain = rows
        .iter()
        .filter(|r| r["pqzVerifyMode"] == "OFFCHAIN")
        .count();
    assert!(offchain >= 2 && rows.len() > offchain, "both verifications");
    for r in rows {
        let mode = match num(&r["modeByte"]) {
            0 => Mode::Hash,
            1 => Mode::Bundle,
            m => panic!("mode {m}"),
        };
        let fee = num(&r["verifierFee"]) as u64;
        let ver = match r["pqzVerifyMode"].as_str().unwrap() {
            "OFFCHAIN" => Verification::Offchain { verifier_fee: fee },
            "PRECOMPILE" => Verification::Precompile,
            m => panic!("{m}"),
        };
        let got = bind_mode(&[0; 32], mode, ver);
        assert_eq!(got, b32(&r["op1Word544"]), "{r}");
        assert_eq!(got, b32(&r["op7Word544"]), "{r}");
    }
    let eb = [0x5a; 32];
    for mode in [Mode::Hash, Mode::Bundle] {
        assert_eq!(
            bind_mode(&eb, mode, Verification::Offchain { verifier_fee: 7 }),
            bind_mode(&eb, mode, Verification::Precompile)
        );
    }
}
