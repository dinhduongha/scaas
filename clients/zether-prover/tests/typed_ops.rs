//! typed-signing C7: the typed digests the prover builds equal the rows of smartcontracts/vectors/typed/typed_ops.json (written by
//! clients/clientkeys, checked against Foundry). The vector is the authority; nothing here is built from a test value.
use serde_json::{json, Value};
use zether_prover::api::call;

/// Rows of the vector the Zether prover does not build, each with its reason: another contract kind's domain (the row has no
/// `zether` domain), so a Zether key never signs it. Any other row without a `zether` domain fails the test.
const NOT_ZETHER: [&str; 27] = [
    // the token kind's own (non-Zether) accounts: UA prepare is a NormalToken / WrappedToken entry
    "PrepareAcc", "UAPrepareAcc",
    // MandateWallet / SmartKeyAccount: signed by their owners' keys, not by a Zether key
    "SetMandate", "SetPayee", "RevokeMandate", "PayUnderMandate", "DelegateRevoke", "AddKey", "RemoveKey", "RotateKey", "SetGuardian",
    "CancelRecovery", "Execute",
    // PQZ tokens: no PQZ builder in this package (PqzAuth is built by clientkeys, e2e.py and the node)
    "PqzTransferSingle", "UAPqzTransferSingle", "PqzTransferSingleCompact", "UAPqzTransferSingleCompact", "PqzTransfer",
    "UAPqzTransfer", "PqzTransferCompact", "UAPqzTransferCompact", "PqzUnshield", "UAPqzUnshield", "PqzUnshieldUnwrap",
    "UAPqzUnshieldUnwrap", "PqzAuth",
    // the DEX's domain
    "CancelDexOrder",
];

fn vector() -> Value {
    let path = format!("{}/../../smartcontracts/vectors/typed/typed_ops.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn req(row: &Value) -> Value {
    let dom = &row["domains"]["zether"]["domain"];
    json!({"chainId": dom["chainId"], "chainUid": dom["salt"], "token": dom["verifyingContract"]})
}

fn merge(mut a: Value, b: Value) -> Value {
    a.as_object_mut().unwrap().extend(b.as_object().unwrap().clone());
    a
}

#[test]
fn every_zether_row_digest_equals_the_vector() {
    let v = vector();
    let ops = v["ops"].as_object().unwrap();
    let (mut zether, mut other) = (0, vec![]);
    for (op, row) in ops {
        let Some(dom) = row["domains"].get("zether") else {
            other.push(op.as_str());
            continue;
        };
        zether += 1;
        let r = merge(req(row), json!({"op": op, "message": row["message"]}));
        let out: Value = serde_json::from_str(&call("typedDigest", &r.to_string()).unwrap()).unwrap();
        assert_eq!(out["typehash"], row["typehash"], "{op} typehash");
        assert_eq!(out["structHash"], row["structHash"], "{op} structHash");
        assert_eq!(out["domainSeparator"], dom["domainSeparator"], "{op} domainSeparator");
        assert_eq!(out["digest"], dom["digest"], "{op} digest");
    }
    assert_eq!(zether, 47, "the vector's Zether rows");
    assert_eq!(zether + other.len(), ops.len());
    let mut want = NOT_ZETHER.to_vec();
    want.sort_unstable();
    other.sort_unstable();
    assert_eq!(other, want, "a row left out must be listed in NOT_ZETHER with its reason");
}

#[test]
fn typed_digest_refuses_unknown_op_missing_and_extra_field() {
    let base = json!({"chainId": 31337, "chainUid": format!("0x{}", "11".repeat(32)), "token": format!("0x{}", "22".repeat(20))});
    let run = |extra: Value| call("typedDigest", &merge(base.clone(), extra).to_string());
    assert!(run(json!({"op": "Nope", "message": {}})).unwrap_err().contains("unknown typed op"));
    let ua = format!("0x{}", "33".repeat(32));
    assert!(run(json!({"op": "ZetherRollOver", "message": {"ua": ua}})).unwrap_err().contains("missing field `accSeq`"));
    let full = json!({"ua": ua, "accSeq": 1, "expectedPendingSeq": 2, "validUntilBlock": 3});
    assert!(run(json!({"op": "ZetherRollOver", "message": full})).is_ok());
    let extra = merge(full.clone(), json!({"extra": 1}));
    assert!(run(json!({"op": "ZetherRollOver", "message": extra})).unwrap_err().contains("no field `extra`"));
    let wide = merge(full, json!({"validUntilBlock": "18446744073709551616"}));
    assert!(run(json!({"op": "ZetherRollOver", "message": wide})).unwrap_err().contains("does not fit uint64"));
}

// ---- the named relayed entry of a prover build ----

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn be32(v: &Value) -> Vec<u8> {
    let n: u64 = v.as_str().map_or_else(|| v.as_u64().unwrap(), |s| s.parse().unwrap());
    let mut o = vec![0u8; 24];
    o.extend(n.to_be_bytes());
    o
}
fn g1(v: &Value) -> Vec<u8> {
    ["x0", "x1", "y0", "y1"].iter().flat_map(|k| h(&v[k])).collect()
}
fn head(a: &Value) -> Vec<u8> {
    ["accSeq", "sendCounter", "validUntilBlock"].iter().flat_map(|k| be32(&a[k])).collect()
}

/// The packed `payload` the prover's builds return, laid out from the vector's `args` (zether.md §10).
fn payload(op: &str, a: &Value) -> Vec<u8> {
    let mut p = head(a);
    match op {
        "ZetherTransferSingle" => {
            p.extend(h(&a["salt"]));
            for k in ["yFrom", "yTo", "cOut", "dOut", "cDeb", "cAud"] {
                p.extend(g1(&a[k]));
            }
        }
        "ZetherTransfer" | "ZetherTransferCompact" => {
            let legs = a["legs"].as_array().unwrap();
            p.extend(h(&a["salt"]));
            p.extend(be32(&json!(legs.len())));
            p.extend(be32(&a["decoyFee"]));
            for k in ["yFrom", "dOut", "cDeb"] {
                p.extend(g1(&a[k]));
            }
            for l in legs {
                for k in ["yTo", "cOut", "cAud", "dAud"] {
                    p.extend(g1(&l[k]));
                }
            }
            let sealed = h(&a["sealedMemo"]);
            if !sealed.is_empty() {
                p.extend([0u8; 16]);
                p.extend(sealed);
            }
        }
        _ => p.extend(g1(&a["yFrom"])),
    }
    p
}

const NAMED: [&str; 5] = ["ZetherTransferSingle", "ZetherTransfer", "ZetherTransferCompact", "ZetherUnshield", "ZetherUnshieldUnwrap"];

#[test]
fn named_call_equals_the_vector_calldata() {
    let v = vector();
    for op in NAMED {
        let row = &v["ops"][op];
        let (m, dom) = (&row["message"], &row["domains"]["zether"]);
        let a = &m["args"];
        let env: Value = ["from", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"].iter().map(|k| (k.to_string(), m[k].clone())).collect::<serde_json::Map<_, _>>().into();
        let mut r = merge(req(row), json!({"op": op, "env": env, "payload": format!("0x{}", hex::encode(payload(op, a))),
            "proof": m["proof"], "beneficiary": a["beneficiaryUA"], "sig": dom["signature"]}));
        for k in ["recipient", "amount", "unwrap"] {
            if m.get(k).is_some() {
                r[k] = m[k].clone();
            }
        }
        let out: Value = serde_json::from_str(&call("namedCall", &r.to_string()).unwrap()).unwrap();
        assert_eq!(out["digest"], dom["digest"], "{op} digest");
        assert_eq!(out["structHash"], row["structHash"], "{op} structHash");
        assert_eq!(out["calldata"], dom["calldata"], "{op} calldata");
        assert_eq!(out["message"]["args"], m["args"], "{op} args");
        // no signature yet: the digest only
        r.as_object_mut().unwrap().remove("sig");
        let out: Value = serde_json::from_str(&call("namedCall", &r.to_string()).unwrap()).unwrap();
        assert_eq!(out["digest"], dom["digest"]);
        assert!(out.get("calldata").is_none());
    }
    // an op without a named builder is refused, its digest is still `typedDigest`'s
    let r = json!({"op": "UABurn", "env": {}, "payload": "0x", "proof": "0x", "beneficiary": "0x"});
    assert!(call("namedCall", &r.to_string()).is_err());
}
