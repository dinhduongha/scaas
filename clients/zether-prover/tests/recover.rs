//! CTR-ZTH-30 / CTR-ZTH-50: `s`, the amounts and every bundle of a transfer from the sender's key and chain data alone
//! (`recoverTransfer`): from storage (no logs; the commitment and its memo, or the stored record) or from calldata; a
//! fresh salt per build; the token's modes in a request (`disclosureMode`, `auditorMode`, CTR-ZTH-38/48/49).

use serde_json::{json, Value};
use zether_prover::api::call;
use zether_prover::curve::keccak256;

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
        let mut no_key = from_storage(curve, &entry(&t), UID);
        no_key["keys"] = json!([y(curve, 1)]);
        assert!(err("recoverTransfer", &no_key).contains("keys"));
    }
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

/// Controller ruling: a BLS12-381 commit-reveal transfer with the auditor at M = 8 (~17.03M gas) is over the EIP-7825
/// cap (16,777,216), so the prover refuses it; one recipient fewer, the auditor left out, or another form builds.
#[test]
fn gas_cap_refuses_bls_compact_auditor_m8() {
    let mut req = multi("bls12381");
    req["recipients"] = json!((1..=8).map(|a| json!({"yTo": y("bls12381", a), "amount": 1})).collect::<Vec<_>>());
    assert!(err("proveTransferMulti", &req).contains("EIP-7825"));
    let mut seven = req.clone();
    seven["recipients"].as_array_mut().unwrap().pop();
    ok("proveTransferMulti", &seven);
    let mut no_aud = req.clone();
    no_aud["yAud"] = Value::Null;
    ok("proveTransferMulti", &no_aud);
    let mut bn = req.clone();
    bn["curve"] = json!("bn254");
    bn["recipients"] = json!((1..=8).map(|a| json!({"yTo": y("bn254", a), "amount": 1})).collect::<Vec<_>>());
    bn["yAud"] = y("bn254", 9);
    bn["acc"] = ok("encrypt", &json!({"curve": "bn254", "Y": y("bn254", 0), "amount": 5000}));
    ok("proveTransferMulti", &bn);
}
