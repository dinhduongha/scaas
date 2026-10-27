//! CTR-ZTH-30 / CTR-ZTH-50: `s`, the amounts and every bundle of a transfer from the sender's key and chain data alone
//! (`recoverTransfer`): from storage (no logs; the stored record `R` and, on commit-reveal, the stored memo; review C0-3)
//! or from calldata; a fresh salt per build; the token's modes in a request (`disclosureMode`, `auditorMode`, CTR-ZTH-38/48/49).

use serde_json::{json, Value};
use zether_prover::api::{self, call};
use zether_prover::curve::{keccak256, Bls12381};
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;

fn ok(cmd: &str, v: &Value) -> Value {
    serde_json::from_str(&call(cmd, &v.to_string()).unwrap()).unwrap()
}

fn err(cmd: &str, v: &Value) -> String {
    call(cmd, &v.to_string()).unwrap_err()
}

/// Curves under test: BLS12-381 only, plus bn254 with the legacy `bn254` feature (`BN` = the cheaper one of them).
#[cfg(feature = "bn254")]
const CURVES: [&str; 2] = ["bn254", "bls12381"];
#[cfg(not(feature = "bn254"))]
const CURVES: [&str; 1] = ["bls12381"];
#[cfg(feature = "bn254")]
const BN: &str = "bn254";
#[cfg(not(feature = "bn254"))]
const BN: &str = "bls12381";

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
        "validUntilBlock": 100, "acc": acc, "balance": 5000, "includeWitness": true, "yAud": y(curve, 9), "disclosureMode": "compact",
        "recipients": [{"yTo": y(curve, 1), "amount": 1200}, {"yTo": y(curve, 2), "amount": 0},
                       {"yTo": y(curve, 3), "amount": 77}],
    })
}

/// The storage-only request: the counter, `transferEntry(entryRef)` (= `R`, a SSTORE2 read on commit-reveal),
/// `transferMemo(entryRef)` and the token's auditor key.
fn from_storage(curve: &str, t: &Value, uid: &str) -> Value {
    json!({"curve": curve, "key": key(0), "chainId": 31337, "chainUid": uid, "token": TOKEN, "sendCounter": 4,
        "entry": t["bundles"], "memo": t["memo"], "yAud": y(curve, 9)})
}

#[test]
fn recover_from_storage_alone() {
    for curve in CURVES {
        let t = ok("proveTransferMulti", &multi(curve));
        assert_eq!(t["mode"], json!("compact"));
        let r = ok("recoverTransfer", &from_storage(curve, &t, UID));
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
        // the indexer's commitment is the hash of the stored R
        assert_eq!(r["commitment"], hx(&keccak256(&hexb(&t["bundles"]))));
        // a tampered memo, another chainUid, a tampered record: refused
        let mut bad = from_storage(curve, &t, UID);
        let mut m = hexb(&t["memo"]);
        m[20] ^= 1;
        bad["memo"] = hx(&m);
        assert!(!err("recoverTransfer", &bad).is_empty(), "tampered memo");
        assert!(!err("recoverTransfer", &from_storage(curve, &t, &format!("0x{}", "25".repeat(32)))).is_empty());
        let mut bad = from_storage(curve, &t, UID);
        let mut r = hexb(&t["bundles"]);
        r[16 + 5] ^= 1;
        bad["entry"] = hx(&r);
        assert!(!err("recoverTransfer", &bad).is_empty(), "tampered record");
    }
}

fn ua(curve: &str, a: u32) -> Value {
    ok("keygen", &json!({"curve": curve, "key": key(a)}))["UA"].clone()
}

/// `openMemo` on the stored memo names the recipients and the auditor flag; the record already carries every `Y_tj`, so
/// `recoverTransfer` needs no key lookup (review C0-3).
#[test]
fn open_memo_names_the_recipients() {
    for curve in CURVES {
        let t = ok("proveTransferMulti", &multi(curve));
        let m = ok("openMemo", &from_storage(curve, &t, UID));
        assert_eq!(m["salt"], t["salt"]);
        assert_eq!(m["auditorIncluded"], json!(true));
        assert_eq!(m["legs"].as_array().unwrap().iter().map(|l| l["toUA"].clone()).collect::<Vec<_>>(),
            vec![json!(ua(curve, 1)), json!(ua(curve, 2)), json!(ua(curve, 3))], "{curve}: the recipients");
        assert_eq!(m["legs"][0]["amount"], json!("1200"));
    }
}

/// Review T1 I2: a commit-reveal payload carries every `Y_tj` (no `keys`) and its memo the amounts (no BSGS: the bound
/// here is far below the amount).
#[test]
fn recover_commit_reveal_calldata_without_keys() {
    let mut req = multi(BN);
    req["balance"] = json!(1u64 << 40);
    req["acc"] = ok("encrypt", &json!({"curve": BN, "Y": y(BN, 0), "amount": 1u64 << 40}));
    req["recipients"][0]["amount"] = json!(1u64 << 33);
    let t = ok("proveTransferMulti", &req);
    let q = json!({"curve": BN, "key": key(0), "chainId": 31337, "chainUid": UID, "token": TOKEN,
        "yAud": y(BN, 9), "tableBits": 10, "boundBits": 20, "payload": t["payload"]});
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
    let mut req = multi(BN);
    req["yAud"] = Value::Null;
    let t = ok("proveTransferMulti", &req);
    let mut q = from_storage(BN, &t, UID);
    q["yAud"] = Value::Null;
    let r = ok("recoverTransfer", &q);
    assert_eq!(r["auditorIncluded"], json!(false));
    assert_eq!(r["bundles"], t["bundles"]);
}

/// A full record (`mtxConfidentialTransfer` on a BUNDLE token, the single format) from storage, and any entry from calldata: the
/// salt in `R` or the payload gives `s`, BSGS the amounts.
#[test]
fn recover_a_record_and_calldata() {
    let mut req = multi(BN);
    req["disclosureMode"] = Value::Null; // a BUNDLE token: `mtxConfidentialTransfer` stores R
    let t = ok("proveTransferMulti", &req);
    assert_eq!(t["memo"], json!("0x"), "no memo off commit-reveal");
    let base = json!({"curve": BN, "key": key(0), "chainId": 31337, "chainUid": UID, "token": TOKEN,
        "yAud": y(BN, 9), "tableBits": 18, "boundBits": 24});
    let mut q = base.clone();
    (q["entry"], q["sendCounter"]) = (t["bundles"].clone(), json!(4));
    let r = ok("recoverTransfer", &q);
    assert_eq!(r["s"], t["witness"]["s"]);
    assert_eq!(r["legs"][0]["amount"], json!("1200"), "BSGS");
    let mut w = q.clone();
    w["yAud"] = y(BN, 8); // review T1 m1: only the record compare refuses a wrong auditor key
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
    let req = multi(BN);
    let (a, b) = (ok("proveTransferMulti", &req), ok("proveTransferMulti", &req));
    assert_ne!(a["salt"], b["salt"]);
    assert_ne!(a["witness"]["s"], b["witness"]["s"]);
    assert_ne!(hexb(&a["memo"])[16..], hexb(&b["memo"])[16..], "memo keystream");
}

/// The default entry follows the token: `mtxConfidentialTransfer` stores R on a BUNDLE token (the default) and commits on a
/// COMPACT token, which refuses the other forms and the single format; `auditorMode` FULL needs `yAud`, NONE refuses it.
#[test]
fn modes_in_the_request() {
    let mut req = multi(BN);
    req["disclosureMode"] = Value::Null;
    let sel = |t: &Value| t["directCalldata"].as_str().unwrap()[2..10].to_string();
    let t = ok("proveTransferMulti", &req);
    assert_eq!(t["mode"], json!("bundle"));
    assert_eq!(sel(&t), "5dc7af97", "mtxConfidentialTransfer, the default");
    let mut h = req.clone();
    h["mode"] = json!("compact");
    let compact = hex::encode(zether_prover::envelope::selector("mtxConfidentialTransferCompact(bytes,bytes,bytes,bytes32,bytes)"));
    assert_eq!(sel(&ok("proveTransferMulti", &h)), compact, "commit-reveal on a BUNDLE token");
    let mut c = req.clone();
    c["disclosureMode"] = json!("compact");
    let t = ok("proveTransferMulti", &c);
    assert_eq!(t["mode"], json!("compact"));
    assert_eq!(sel(&t), "5dc7af97", "mtxConfidentialTransfer: commit-reveal on a COMPACT token");
    c["mode"] = json!("bundle");
    assert!(err("proveTransferMulti", &c).contains("TransferEntryDisabled"));
    c["mode"] = json!("none");
    assert!(err("proveTransferMulti", &c).contains("compact"), "the NONE form is retired (review C0-3)");
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

/// Review T1 I1, final review I1: over the EIP-7825 cap the refusal names the cap, the measured gas limit at this `M`,
/// the most recipients the form takes and the cheaper forms that fit (here BLS12-381 commit-reveal with the auditor at
/// M = 8, direct: at most 7; one cheaper form fits at M = 8).
#[test]
fn gas_cap_message() {
    let mut req = multi("bls12381");
    req["recipients"] = json!((1..=8).map(|a| json!({"yTo": y("bls12381", a), "amount": 1})).collect::<Vec<_>>());
    let e = err("proveTransferMulti", &req);
    for part in ["EIP-7825", "16777216", "M = 8", "16941647", "at most 7 recipients", "bls12381 compact with the auditor, direct",
        "a cheaper form: compact without the auditor (~16580056)"] {
        assert!(e.contains(part), "{part}: {e}");
    }
    #[cfg(feature = "bn254")]
    {
    let mut bn = multi(BN);
    bn["disclosureMode"] = Value::Null;
    bn["recipients"] = json!((1..=9).map(|a| json!({"yTo": y(BN, a), "amount": 1})).collect::<Vec<_>>());
    let e = err("proveTransferMulti", &bn);
    assert!(e.contains("bn254 bundle with the auditor, direct, M = 9") && e.contains("at most 8"), "{e}");
    assert!(e.contains("compact without the auditor (~16381440)"), "{e}");
    }
}

/// Review2 C3-2: a relayed build names how it is relayed, so the gas check never takes the `mtxExecute` figures for a
/// `uaExecute` relay. BLS12-381 compact with the auditor at M = 7 is 15.6 M relayed through `mtxExecute`, 18.1 M through
/// an `fndsa512` UA.
#[test]
fn a_relayed_build_names_its_signer_kind() {
    let mut req = multi("bls12381");
    req["recipients"] = json!((1..=7).map(|a| json!({"yTo": y("bls12381", a), "amount": 1})).collect::<Vec<_>>());
    req["envelopeBinding"] = json!(format!("0x{}", "33".repeat(32)));
    assert!(err("proveTransferMulti", &req).contains("needs `uaSigner`"));
    req["uaSigner"] = json!("nope");
    assert!(err("proveTransferMulti", &req).contains("must be"));
    req["uaSigner"] = json!("fndsa512");
    assert!(err("proveTransferMulti", &req).contains("EIP-7825"), "over the cap through a UA");
    req["uaSigner"] = json!("ecdsa");
    ok("proveTransferMulti", &req);
    // the other accounts.md kinds: 15.63 M relayed + the cap builds under 16.78 M for the light kinds (ed25519 0.21 M,
    // p256 / webauthn-p256 0.4 M), is refused for the heavy ones (slhdsa128s 1.4 M, mldsa44 4.25 M)
    for k in ["ed25519", "p256", "webauthn-p256"] {
        req["uaSigner"] = json!(k);
        ok("proveTransferMulti", &req);
    }
    for k in ["slhdsa128s", "mldsa44"] {
        req["uaSigner"] = json!(k);
        assert!(err("proveTransferMulti", &req).contains("EIP-7825"), "{k}");
    }
    // anything else (an msig) passes its own number
    req.as_object_mut().unwrap().remove("uaSigner");
    req["uaSignerGas"] = json!(123_456);
    ok("proveTransferMulti", &req);
    req["uaSignerGas"] = json!(2_000_000);
    assert!(err("proveTransferMulti", &req).contains("EIP-7825"));
    req["uaSigner"] = json!("ecdsa");
    assert!(err("proveTransferMulti", &req).contains("not both"));
    req.as_object_mut().unwrap().remove("uaSignerGas");
    req["uaSigner"] = json!("ecdsa");
    // a direct build takes none
    let mut d = multi("bls12381");
    d["uaSigner"] = json!("ecdsa");
    assert!(err("proveTransferMulti", &d).contains("needs an `envelopeBinding`"));
}
