//! CTR-ZTH-30 / CTR-ZTH-50: `s`, the amounts and every bundle of a transfer from the sender's key and chain data alone
//! (`recoverTransfer`): from storage (no logs; the commitment and its memo, or the stored record) or from calldata; a
//! fresh salt per build; the token's modes in a request (`disclosureMode`, `auditorMode`, CTR-ZTH-38/48/49).

use serde_json::{json, Value};
use zether_prover::api::{self, call};
use zether_prover::curve::{keccak256, Bls12381, Bn254};

fn ok(cmd: &str, v: &Value) -> Value {
    serde_json::from_str(&call(cmd, &v.to_string()).unwrap()).unwrap()
}

fn err(cmd: &str, v: &Value) -> String {
    call(cmd, &v.to_string()).unwrap_err()
}

const UID: &str = "0x2424242424242424242424242424242424242424242424242424242424242424";
const TOKEN: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";

fn key(account: u32) -> Value {
    json!({"seed": format!("0x{}", "07".repeat(64)), "coin": 60, "account": account})
}

fn y(curve: &str, a: u32) -> Value {
    ok("keygen", &json!({"curve": curve, "key": key(a)}))["Y"].clone()
}

fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(&v.as_str().unwrap()[2..]).unwrap()
}

fn hx(b: &[u8]) -> Value {
    json!(format!("0x{}", hex::encode(b)))
}

/// A commit-reveal transfer on a COMPACT token (its default entry): three recipients, one a decoy, the auditor in.
fn multi(curve: &str) -> Value {
    let acc = ok("encrypt", &json!({"curve": curve, "Y": y(curve, 0), "amount": 5000}));
    json!({
        "curve": curve, "key": key(0), "chainId": 31337, "chainUid": UID, "token": TOKEN, "sendCounter": 4, "accSeq": 1,
        "acc": acc, "balance": 5000, "includeWitness": true, "yAud": y(curve, 9), "disclosureMode": "compact",
        "recipients": [{"yTo": y(curve, 1), "amount": 1200}, {"yTo": y(curve, 2), "amount": 0},
                       {"yTo": y(curve, 3), "amount": 77}],
    })
}

/// What `transferEntry(entryRef)` returns after a commit-reveal transfer: `keccak256(R) ‖ memo`.
fn entry(t: &Value) -> Value {
    hx(&[keccak256(&hexb(&t["bundles"])).to_vec(), hexb(&t["memo"])].concat())
}

/// The storage-only request: the counter, the entry, the registry's keys (`keyOf`) and the token's auditor key.
fn from_storage(curve: &str, entry: &Value, uid: &str) -> Value {
    json!({"curve": curve, "key": key(0), "chainId": 31337, "chainUid": uid, "token": TOKEN, "sendCounter": 4,
        "entry": entry, "keys": [y(curve, 3), y(curve, 1), y(curve, 2), y(curve, 5)], "yAud": y(curve, 9)})
}

#[test]
fn recover_from_storage_alone() {
    for curve in ["bn254", "bls12381"] {
        let t = ok("proveTransferMulti", &multi(curve));
        assert_eq!(t["mode"], json!("compact"));
        let r = ok("recoverTransfer", &from_storage(curve, &entry(&t), UID));
        assert_eq!(r["s"], t["witness"]["s"], "{curve}: s");
        assert_eq!(r["salt"], t["salt"]);
        assert_eq!(r["bundles"], t["bundles"], "{curve}: R, every leg");
        assert_eq!(r["entryRef"], t["entryRef"]);
        assert_eq!(r["legs"][0]["amount"], json!("1200"));
        assert_eq!(r["legs"][2]["amount"], json!("77"));
        assert_eq!(r["legs"][2]["yTo"], y(curve, 3));
        assert_eq!(r["auditorIncluded"], json!(true));
        assert_eq!(r["senderS"].as_str().unwrap().len(), 2 + 64);
        assert_eq!(r["senderCp"].as_array().unwrap().len(), 3);
        // a tampered memo, another chainUid, a missing key: refused
        let mut bad = hexb(&entry(&t));
        bad[32 + 20] ^= 1;
        assert!(!err("recoverTransfer", &from_storage(curve, &hx(&bad), UID)).is_empty(), "tampered memo");
        assert!(!err("recoverTransfer", &from_storage(curve, &entry(&t), &format!("0x{}", "25".repeat(32)))).is_empty());
        let mut c = hexb(&entry(&t));
        c[3] ^= 1;
        assert!(err("recoverTransfer", &from_storage(curve, &hx(&c), UID)).contains("rebuilt"), "tampered commitment");
    }
}

/// The key-lookup source for a storage-only recovery: the registry's `keyOf(toUA)`, here a map of the registered keys
/// (accounts 1–5), counting the calls.
fn registry(curve: &str) -> std::collections::HashMap<[u8; 32], Vec<u8>> {
    (1..=5).map(|a| (hexb(&ua(curve, a)).try_into().unwrap(), hexb(&y(curve, a)))).collect()
}

fn ua(curve: &str, a: u32) -> Value {
    ok("keygen", &json!({"curve": curve, "key": key(a)}))["UA"].clone()
}

fn recover_with(curve: &str, q: &Value, key_of: &mut dyn FnMut(&[u8; 32]) -> Option<Vec<u8>>) -> Result<Value, String> {
    let mut rng = rand_core::OsRng;
    match curve {
        "bn254" => api::recover_transfer_with::<Bn254, _>(q, key_of, &mut rng),
        _ => api::recover_transfer_with::<Bls12381, _>(q, key_of, &mut rng),
    }
}

/// Review T1 I2: from the seed and contract reads only. `openMemo` on `transferEntry(entryRef)` names the recipients,
/// their keys come from `keyOf` (no `keys` in the request), the auditor key from `auditorKey()`; with part of the keys
/// given, only the rest is fetched; a missing key names every missing UA; a lookup that answers another UA's key or
/// garbage is refused (fail closed).
#[test]
fn recover_with_keys_from_the_registry() {
    for curve in ["bn254", "bls12381"] {
        let t = ok("proveTransferMulti", &multi(curve));
        let mut q = from_storage(curve, &entry(&t), UID);
        q["keys"] = Value::Null;
        let m = ok("openMemo", &q);
        assert_eq!(m["salt"], t["salt"]);
        assert_eq!(m["auditorIncluded"], json!(true));
        assert_eq!(m["needKeys"], json!([ua(curve, 1), ua(curve, 2), ua(curve, 3)]), "{curve}: the UAs to look up");
        assert_eq!(m["legs"][0]["amount"], json!("1200"));
        let reg = registry(curve);
        let mut calls = 0;
        let r = recover_with(curve, &q, &mut |u| {
            calls += 1;
            reg.get(u).cloned()
        })
        .unwrap();
        assert_eq!((r["bundles"].clone(), r["s"].clone(), calls), (t["bundles"].clone(), t["witness"]["s"].clone(), 3));
        // part of the keys given: only the others are fetched
        q["keys"] = json!([y(curve, 2)]);
        let mut calls = 0;
        let r = recover_with(curve, &q, &mut |u| {
            calls += 1;
            reg.get(u).cloned()
        })
        .unwrap();
        assert_eq!((r["bundles"].clone(), calls), (t["bundles"].clone(), 2));
        // without a lookup: every missing UA named
        let e = err("recoverTransfer", &q);
        assert!(e.contains(ua(curve, 1).as_str().unwrap()) && e.contains(ua(curve, 3).as_str().unwrap()), "{e}");
        assert!(!e.contains(ua(curve, 2).as_str().unwrap()));
        // a lookup answering another account's key, or garbage: refused
        q["keys"] = Value::Null;
        assert!(recover_with(curve, &q, &mut |_| Some(hexb(&y(curve, 4)))).unwrap_err().contains("no key for"));
        assert!(recover_with(curve, &q, &mut |_| Some(vec![1, 2, 3])).unwrap_err().contains("no key for"));
        // a tampered memo opens to other UAs: no key, or a rebuilt record that misses the commitment
        let mut bad = hexb(&entry(&t));
        bad[32 + 20] ^= 1;
        q["entry"] = hx(&bad);
        assert!(recover_with(curve, &q, &mut |u| reg.get(u).cloned()).is_err(), "tampered memo");
    }
}

/// Review T1 I2: a commit-reveal payload carries every `Y_tj` (no `keys`) and its memo the amounts (no BSGS: the bound
/// here is far below the amount).
#[test]
fn recover_commit_reveal_calldata_without_keys() {
    let mut req = multi("bn254");
    req["balance"] = json!(1u64 << 40);
    req["acc"] = ok("encrypt", &json!({"curve": "bn254", "Y": y("bn254", 0), "amount": 1u64 << 40}));
    req["recipients"][0]["amount"] = json!(1u64 << 33);
    let t = ok("proveTransferMulti", &req);
    let q = json!({"curve": "bn254", "key": key(0), "chainId": 31337, "chainUid": UID, "token": TOKEN,
        "yAud": y("bn254", 9), "tableBits": 10, "boundBits": 20, "payload": t["payload"]});
    let r = ok("recoverTransfer", &q);
    assert_eq!(r["bundles"], t["bundles"]);
    assert_eq!(r["legs"][0]["amount"], json!((1u64 << 33).to_string()));
    assert_eq!(ok("openMemo", &q)["legs"][2]["amount"], json!("77"), "openMemo on calldata too");
    let mut bad = hexb(&t["payload"]);
    let n = bad.len();
    bad[n - 30] ^= 1; // the memo
    let mut q2 = q.clone();
    q2["payload"] = hx(&bad);
    assert!(!err("recoverTransfer", &q2).is_empty(), "tampered memo in calldata");
}

/// An `OPTIONAL` opt-out: the memo's flag says the auditor was left out; no `yAud` needed.
#[test]
fn recover_an_opt_out() {
    let mut req = multi("bn254");
    req["yAud"] = Value::Null;
    let t = ok("proveTransferMulti", &req);
    let mut q = from_storage("bn254", &entry(&t), UID);
    q["yAud"] = Value::Null;
    let r = ok("recoverTransfer", &q);
    assert_eq!(r["auditorIncluded"], json!(false));
    assert_eq!(r["bundles"], t["bundles"]);
}

/// A full record (`zetherTransfer` on a BUNDLE token, the single format) from storage, and any entry from calldata: the
/// salt in `R` or the payload gives `s`, BSGS the amounts.
#[test]
fn recover_a_record_and_calldata() {
    let mut req = multi("bn254");
    req["disclosureMode"] = Value::Null; // a BUNDLE token: `zetherTransfer` stores R
    let t = ok("proveTransferMulti", &req);
    assert_eq!(t["memo"], json!("0x"), "no memo off commit-reveal");
    let base = json!({"curve": "bn254", "key": key(0), "chainId": 31337, "chainUid": UID, "token": TOKEN,
        "yAud": y("bn254", 9), "tableBits": 18, "boundBits": 24});
    let mut q = base.clone();
    (q["entry"], q["sendCounter"]) = (t["bundles"].clone(), json!(4));
    let r = ok("recoverTransfer", &q);
    assert_eq!(r["s"], t["witness"]["s"]);
    assert_eq!(r["legs"][0]["amount"], json!("1200"), "BSGS");
    let mut w = q.clone();
    w["yAud"] = y("bn254", 8); // review T1 m1: only the record compare refuses a wrong auditor key
    assert!(err("recoverTransfer", &w).contains("rebuilt"), "wrong yAud on a record");
    let mut q = base.clone();
    q["payload"] = t["payload"].clone();
    assert_eq!(ok("recoverTransfer", &q)["bundles"], t["bundles"], "from calldata");
    let mut one = req.clone();
    (one["yTo"], one["amount"]) = (req["recipients"][0]["yTo"].clone(), json!(1200));
    let t1 = ok("proveTransfer", &one);
    let mut q = base.clone();
    (q["entry"], q["sendCounter"]) = (t1["record"].clone(), json!(4));
    let r1 = ok("recoverTransfer", &q);
    assert_eq!(r1["s"], t1["witness"]["s"], "single");
    assert_eq!(r1["legs"][0]["amount"], json!("1200"));
    q["key"] = key(1);
    assert!(err("recoverTransfer", &q).contains("D_out"), "another key");
}

/// A retry at the same counter (the first transaction failed, its calldata public): a fresh salt, so another memo key
/// and another `s`.
#[test]
fn two_builds_at_one_counter_differ() {
    let req = multi("bn254");
    let (a, b) = (ok("proveTransferMulti", &req), ok("proveTransferMulti", &req));
    assert_ne!(a["salt"], b["salt"]);
    assert_ne!(a["witness"]["s"], b["witness"]["s"]);
    assert_ne!(hexb(&a["memo"])[16..], hexb(&b["memo"])[16..], "memo keystream");
}

/// The default entry follows the token: `zetherTransfer` stores R on a BUNDLE token (the default) and commits on a
/// COMPACT token, which refuses the other forms and the single format; `auditorMode` FULL needs `yAud`, NONE refuses it.
#[test]
fn modes_in_the_request() {
    let mut req = multi("bn254");
    req["disclosureMode"] = Value::Null;
    let sel = |t: &Value| t["directCalldata"].as_str().unwrap()[2..10].to_string();
    let t = ok("proveTransferMulti", &req);
    assert_eq!(t["mode"], json!("bundle"));
    assert_eq!(sel(&t), "d228e5c0", "zetherTransfer, the default");
    let mut h = req.clone();
    h["mode"] = json!("compact");
    let compact = hex::encode(zether_prover::envelope::selector("zetherTransferCompact(bytes,bytes,bytes,bytes32)"));
    assert_eq!(sel(&ok("proveTransferMulti", &h)), compact, "commit-reveal on a BUNDLE token");
    let mut c = req.clone();
    c["disclosureMode"] = json!("compact");
    let t = ok("proveTransferMulti", &c);
    assert_eq!(t["mode"], json!("compact"));
    assert_eq!(sel(&t), "d228e5c0", "zetherTransfer: commit-reveal on a COMPACT token");
    for m in ["bundle", "none"] {
        c["mode"] = json!(m);
        assert!(err("proveTransferMulti", &c).contains("TransferEntryDisabled"));
    }
    let mut one = c.clone();
    (one["yTo"], one["amount"]) = (req["recipients"][0]["yTo"].clone(), json!(1));
    assert!(err("proveTransfer", &one).contains("TransferEntryDisabled"), "no single format on COMPACT");
    let mut a = req.clone();
    a["auditorMode"] = json!("none");
    assert!(err("proveTransferMulti", &a).contains("AuditorForbidden"));
    a["yAud"] = Value::Null;
    a["auditorMode"] = json!("full");
    assert!(err("proveTransferMulti", &a).contains("AuditorRequired"));
    a["auditorMode"] = json!("optional");
    ok("proveTransferMulti", &a);
}

/// Review T1 I1: over the EIP-7825 cap the refusal names the cap, the estimate at this `M`, the most recipients the form
/// takes and the cheaper forms that fit (here BLS12-381 commit-reveal with the auditor at M = 8: none fits, at most 7).
#[test]
fn gas_cap_message() {
    let mut req = multi("bls12381");
    req["recipients"] = json!((1..=8).map(|a| json!({"yTo": y("bls12381", a), "amount": 1})).collect::<Vec<_>>());
    let e = err("proveTransferMulti", &req);
    for part in ["EIP-7825", "16777216", "M = 8", "17027455", "at most 7 recipients", "bls12381 compact with the auditor",
        "none without the auditor (~16316347)"] {
        assert!(e.contains(part), "{part}: {e}");
    }
    let mut bn = multi("bn254");
    bn["disclosureMode"] = Value::Null;
    bn["recipients"] = json!((1..=9).map(|a| json!({"yTo": y("bn254", a), "amount": 1})).collect::<Vec<_>>());
    let e = err("proveTransferMulti", &bn);
    assert!(e.contains("bn254 bundle with the auditor, M = 9") && e.contains("at most 8"), "{e}");
    assert!(e.contains("compact with the auditor (~16076281)") && e.contains("none without the auditor"), "{e}");
}
