// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Group 3l (wrap limits spec 2026-11-10 §2.1, §9): `scaas_ua::wraplimit` against the files clientkeys and the generator write:
//! the router's `UASetWrapLimits` / `UASetWrapMember` rows of `typed/typed_ops.json` (type string, struct hash, digest; a
//! non-zero unbound `relayer` / `feeRecipient` hashed as 0) and every row of `wraplimits/wraplimits.json` (the base, the
//! weighted start and the entitlement after each step, as forge replays them on the contract).
use scaas_ua::regulated::{router_domain_separator, Envelope};
use scaas_ua::wraplimit::{
    digest, set_wrap_limits_struct_hash, set_wrap_limits_type, set_wrap_member_struct_hash, set_wrap_member_type, NetLine,
    WrapLegLimits, WrapLimit,
};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
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
    v.as_u64().map(u128::from).unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
fn uint_word(v: &Value) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&num(v).to_be_bytes());
    w
}
fn envelope(m: &Value) -> Envelope {
    Envelope {
        from: b32(&m["from"]),
        batch: uint_word(&m["batch"]),
        nonce: uint_word(&m["nonce"]),
        valid_until: uint_word(&m["validUntil"]),
        mode: num(&m["mode"]) as u32,
        relayer: b20(&m["relayer"]),
        fee: uint_word(&m["fee"]),
        fee_recipient: b20(&m["feeRecipient"]),
    }
}
fn limit(v: &Value) -> WrapLimit {
    WrapLimit { per_user: num(&v["perUser"]) as u32, token_wide: num(&v["tokenWide"]) as u64, period: num(&v["period"]) as u32 }
}

#[test]
fn typed_ops_wrap_limit_rows() {
    let v = load("typed/typed_ops.json");
    for op in ["UASetWrapLimits", "UASetWrapMember"] {
        let r = &v["ops"][op];
        let ty = if op == "UASetWrapLimits" { set_wrap_limits_type() } else { set_wrap_member_type() };
        assert_eq!(ty, r["typeString"].as_str().unwrap(), "{op}");
        let m = &r["message"];
        let d = &r["domains"]["gov_router"];
        let dom = &d["domain"];
        let ds = router_domain_separator(num(&dom["chainId"]) as u64, &b20(&dom["verifyingContract"]), &b32(&dom["salt"]));
        let (e, target) = (envelope(m), b20(&m["target"]));
        let sh = |e: &Envelope| if op == "UASetWrapLimits" {
            let legs: Vec<WrapLegLimits> = m["legs"].as_array().unwrap().iter().map(|l| WrapLegLimits {
                underlying: b20(&l["underlying"]), unit_exp: num(&l["unitExp"]) as u8, decay_days: num(&l["decayDays"]) as u16,
                wrap_short: limit(&l["wrapShort"]), wrap_long: limit(&l["wrapLong"]), unwrap_short: limit(&l["unwrapShort"]),
                unwrap_long: limit(&l["unwrapLong"]),
            }).collect();
            set_wrap_limits_struct_hash(e, &target, &legs, m["netUnwrap"].as_bool().unwrap(), m["wrapList"].as_bool().unwrap(),
                m["unwrapList"].as_bool().unwrap())
        } else {
            set_wrap_member_struct_hash(e, &target, &b32(&m["account"]), m["canWrap"].as_bool().unwrap(),
                m["canUnwrap"].as_bool().unwrap())
        };
        assert_eq!(sh(&e), b32(&r["structHash"]), "{op}");
        assert_eq!(digest(&ds, &sh(&e)), b32(&d["digest"]), "{op}");
        let unbound = Envelope { fee_recipient: [0xba; 20], ..e };
        assert_eq!(digest(&ds, &sh(&unbound)), b32(&d["digest"]), "{op}: an unbound feeRecipient hashes as 0");
    }
}

#[test]
fn wraplimits_rows() {
    let v = load("wraplimits/wraplimits.json");
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 8);
    for r in rows {
        let (unit, d) = (10u128.pow(num(&r["unitExp"]) as u32), num(&r["decayDays"]) as u16);
        let mut t = num(&r["t0"]) as u64;
        let mut line = NetLine::default();
        for (s, a) in r["steps"].as_array().unwrap().iter().zip(r["after"].as_array().unwrap()) {
            let x = num(&s["value"]);
            match s["op"].as_str().unwrap() {
                "warp" => t += x as u64,
                "wrap" => line.credit((x / unit) as u64, d, t / 60),
                _ => line.debit(x.div_ceil(unit) as u64, d, t / 60),
            }
            let name = r["name"].as_str().unwrap();
            assert_eq!(line.base as u128, num(&a["base"]), "{name}");
            assert_eq!(line.start_min as u128, num(&a["startMin"]), "{name}");
            assert_eq!(line.entitlement(d, t / 60) as u128 * unit, num(&a["entitlement"]), "{name}");
        }
    }
}

/// Round 3s (spec 2026-11-10-token-lists.md §6.2, §10): the router's list ops and `UAEnableFeature`, struct hash and digest
/// of each `typed_ops.json` row (ua-rs signs every kind), an unbound `feeRecipient` hashing as 0.
#[test]
fn typed_ops_list_rows() {
    use scaas_ua::regulated::{enable_feature_struct_hash, enable_feature_type, set_list_struct_hash, set_list_type};
    let v = load("typed/typed_ops.json");
    for op in ["UASetAllowed", "UASetDenied", "UAEnableFeature"] {
        let r = &v["ops"][op];
        let ty = if op == "UAEnableFeature" { enable_feature_type() } else { set_list_type(op == "UASetAllowed") };
        assert_eq!(ty, r["typeString"].as_str().unwrap(), "{op}");
        let m = &r["message"];
        let d = &r["domains"]["gov_router"];
        let dom = &d["domain"];
        let ds = router_domain_separator(num(&dom["chainId"]) as u64, &b20(&dom["verifyingContract"]), &b32(&dom["salt"]));
        let (e, target) = (envelope(m), b20(&m["target"]));
        let sh = |e: &Envelope| if op == "UAEnableFeature" {
            enable_feature_struct_hash(e, &target, num(&m["bit"]) as u8)
        } else {
            let accounts: Vec<[u8; 32]> = m["accounts"].as_array().unwrap().iter().map(b32).collect();
            set_list_struct_hash(op == "UASetAllowed", e, &target, &accounts, m["on"].as_bool().unwrap())
        };
        assert_eq!(sh(&e), b32(&r["structHash"]), "{op}");
        assert_eq!(digest(&ds, &sh(&e)), b32(&d["digest"]), "{op}");
        let relayer = if e.mode & 1 == 0 { [0xbb; 20] } else { e.relayer };
        let unbound = Envelope { fee_recipient: [0xba; 20], relayer, ..e };
        assert_eq!(digest(&ds, &sh(&unbound)), b32(&d["digest"]), "{op}: an unbound relayer and feeRecipient hash as 0");
    }
}
