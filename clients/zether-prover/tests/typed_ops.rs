//! typed-signing C7: the typed digests the prover builds equal the rows of smartcontracts/vectors/typed/typed_ops.json (written by
//! clients/clientkeys, checked against Foundry). The vector is the authority; nothing here is built from a test value.
use serde_json::{json, Value};
use zether_prover::api::call;

/// Rows of the vector the Zether prover does not build, each with its reason: another contract kind's domain (the row has no
/// `zether` domain), so a Zether key never signs it. Any other row without a `zether` domain fails the test.
const NOT_ZETHER: [&str; 80] = [
    // the token kind's own (non-Zether) accounts: UA prepare is a NormalToken / WrappedToken entry
    "UAPrepareAcc",
    // SmartKeyAccount: signed by its owner's keys, not by a Zether key
    "AddKey", "RemoveKey", "RotateKey", "SetGuardian", "CancelRecovery", "CancelNonce", "Execute",
    // MandateWallet (Q6, MD-11): signed by its owner's or delegate's key, not by a Zether key
    "UASetMandate", "UASetPayee", "UARevokeMandate", "UAPayUnderMandate", "UADelegateRevoke", "UAExecute",
    // PQZ tokens: no PQZ builder in this package (PqzAuth is built by clientkeys, e2e.py and the node)
    "UAPqzTransferSingle", "UAPqzTransferSingleCompact", "UAPqzTransfer", "UAPqzTransferCompact", "UAPqzUnshield",
    "UAPqzUnshieldUnwrap", "PqzAuth", "UAPqzRollOver",
    // the DEX's domain
    "CancelDexOrder",
    // the GovernanceRouter's domain (governance spec §3.2): the closed table on its merged entries; signed by an admin's or
    // holder's key through the router, never by a Zether key
    "UAGrantRole", "UARevokeRole", "UASetGrant", "UACancelGrant", "UADisableFeature", "UATransferAdmin",
    "UAAcceptAdmin", "UARenounceAdmin", "UARenounceRole", "UAMint", "UAMintToUA", "UADisableWrap", "UAProposeRate",
    "UACancelRate", "UAExecuteRate", "UASetMarket", "UASetExchangeTarget", "UASetListedOnly", "UASetFeeSplit",
    // ua-mtx-merge T34: the regulated kinds' controls on the router (regulated-kinds spec §3.1); public balances only
    "UAFreeze", "UAUnfreeze", "UAForceTransfer", "UAPause", "UAUnpause", "UARecordOrder", "UARevokeOrder", "UAOperatorTransfer",
    // pay-meta-tax T39 / T41: bit 23's two router ops
    "UASetTaxRate", "UASetTaxRecipient",
    // ua-mtx-merge T76: the factory's creations through the router (chain-neutral spec §4.4)
    "UACreateToken", "UACreateDex", "UACreateInstance",
    // group 3f: the PQZ verifier UA of the PQZ kinds on the router (PQZ verifier mode spec §4.2, §4.3); no Zether token has one
    "UAPqzSetVerifier", "UAPqzCancelVerifier", "UAPqzRevokeVerifier",
    // group 3h T61: bit 24's router op
    "UASetProofStore",
    "UASetVerifierFee", // round 3t (CTR-PQZ-36): the PQZ verifier fee router op
    // group 3l: the two wrap-limit router ops (bit 26 and the wrapped kinds' admin); no Zether key signs them
    "UASetWrapLimits", "UASetWrapMember",
    // round 3r (CTR-GOV-23): the factory's and a compliance registry's admin ops on the router; signed by that admin's key
    "UAPublishTokenEnv", "UAPublishDexEnv", "UAPublishClassEnv", "UADeprecateToken", "UADeprecateDex", "UADeprecateRelease",
    "UASetTokenKindEnabled", "UASetClassKindEnabled", "UASetKycProvider", "UASetCompliance", "UASetChainEntries",
    "UAApproveTokenRelease", "UAApproveDexRelease", "UAApproveRelease", "UARevokeApproval",
    // round 3s (CTR-GOV-24): the router's list edits and enableFeature, no Zether statement
    "UASetAllowed", "UASetDenied", "UAEnableFeature",
];

fn vector() -> Value {
    // ua-mtx-merge T12: the 68-row file of the merged entries (MD-7); the 112-row one and its test are in legacy/ua-mtx-merge/
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
    assert_eq!(zether, 28, "the vector's Zether rows (pay-meta-tax T41: + UAPayWithTax)");
    assert_eq!(zether + other.len(), ops.len());
    let mut want = NOT_ZETHER.to_vec();
    want.sort_unstable();
    other.sort_unstable();
    assert_eq!(other, want, "a row left out must be listed in NOT_ZETHER with its reason");
}

/// CRV I1: `MetaTxLib.canon`. A `relayer` / `feeRecipient` the mode does not bind hashes as 0, on the envelope and on a nested
/// payment, as the contract, clientkeys and the node do; the vector's own messages are canonical, so they cannot show this.
#[test]
fn unbound_relayer_and_fee_recipient_hash_as_zero() {
    let v = vector();
    let digest = |op: &str, edit: &dyn Fn(&mut Value)| -> Value {
        let row = &v["ops"][op];
        let mut message = row["message"].clone();
        edit(&mut message);
        let r = merge(req(row), json!({"op": op, "message": message}));
        let out: Value = serde_json::from_str(&call("typedDigest", &r.to_string()).unwrap()).unwrap();
        out["digest"].clone()
    };
    let (zero, other) = (format!("0x{}", "00".repeat(20)), format!("0x{}", "ab".repeat(20)));
    let set = |m: &mut Value, mode: u64, field: &str, addr: &str| {
        m["mode"] = json!(mode);
        m[field] = json!(addr);
    };

    // `UABurn`'s mode 19 binds both: bit 1 relayer, bit 2 fee recipient
    assert_eq!(digest("UABurn", &|_| ()), v["ops"]["UABurn"]["domains"]["zether"]["digest"], "the row itself");
    for (field, mode) in [("relayer", 18u64), ("feeRecipient", 17)] {
        let named = digest("UABurn", &|m| set(m, mode, field, &other));
        assert_eq!(named, digest("UABurn", &|m| set(m, mode, field, &zero)), "{field} unbound hashes as 0");
        // the control: the same address bound moves the digest
        let bound = digest("UABurn", &|m| set(m, 19, field, &other));
        assert_ne!(bound, digest("UABurn", &|m| set(m, 19, field, &zero)), "{field} bound is hashed");
    }

    // a nested payment: `UAReceiverFee`'s mode 1 binds the relayer only
    let row = &v["ops"]["UAReceiverFee"]["domains"]["zether"]["digest"];
    assert_eq!(&digest("UAReceiverFee", &|m| m["payment"]["feeRecipient"] = json!(other)), row, "nested fee recipient unbound");
    let bound = digest("UAReceiverFee", &|m| set(&mut m["payment"], 3, "feeRecipient", &other));
    assert_ne!(bound, digest("UAReceiverFee", &|m| set(&mut m["payment"], 3, "feeRecipient", &zero)), "nested, bound");
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
        "UAZetherTransferSingle" => {
            p.extend(h(&a["salt"]));
            for k in ["yFrom", "yTo", "cOut", "dOut", "cDeb", "cAud"] {
                p.extend(g1(&a[k]));
            }
        }
        "UAZetherTransfer" | "UAZetherTransferCompact" => {
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

/// The merged entries a prover build is relayed through (R35): `mtx<Op>(UAEnvelope e, <op>, bytes proof, UASig auth)`.
const NAMED: [&str; 5] = ["UAZetherTransferSingle", "UAZetherTransfer", "UAZetherTransferCompact", "UAZetherUnshield", "UAZetherUnshieldUnwrap"];

/// The `namedCall` request of the vector's row `op`, `sig` as given.
fn named_req(v: &Value, op: &str, sig: Value) -> Value {
    let row = &v["ops"][op];
    let m = &row["message"];
    let env: Value = ["from", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"].iter().map(|k| (k.to_string(), m[k].clone())).collect::<serde_json::Map<_, _>>().into();
    let mut r = merge(req(row), json!({"op": op, "env": env, "payload": format!("0x{}", hex::encode(payload(op, &m["args"]))),
        "proof": m["proof"], "beneficiary": m["args"]["beneficiaryUA"], "sig": sig}));
    for k in ["recipient", "amount", "unwrap"] {
        if m.get(k).is_some() {
            r[k] = m[k].clone();
        }
    }
    r
}

fn named(r: &Value) -> Value {
    serde_json::from_str(&call("namedCall", &r.to_string()).unwrap()).unwrap()
}

#[test]
fn named_call_equals_the_vector_calldata() {
    let v = vector();
    for op in NAMED {
        let row = &v["ops"][op];
        let (m, dom) = (&row["message"], &row["domains"]["zether"]);
        // a native id signs with its own key: `UASig{signature}`, as the vector's calldata carries it
        let mut r = named_req(&v, op, dom["signature"].clone());
        let out = named(&r);
        assert_eq!(out["digest"], dom["digest"], "{op} digest");
        assert_eq!(out["structHash"], row["structHash"], "{op} structHash");
        assert_eq!(out["calldata"], dom["calldata"], "{op} calldata");
        assert_eq!(out["message"]["args"], m["args"], "{op} args");
        assert_eq!(out["message"]["from"], m["from"], "{op} from, the bytes32 id");
        // the same signature as an explicit `UASig` object
        assert_eq!(named(&named_req(&v, op, json!({"signature": dom["signature"]})))["calldata"], dom["calldata"], "{op} UASig object");
        // no signature yet: the digest only
        r.as_object_mut().unwrap().remove("sig");
        let out = named(&r);
        assert_eq!(out["digest"], dom["digest"]);
        assert!(out.get("calldata").is_none());
    }
    // an op without a named builder is refused, its digest is still `typedDigest`'s; so is a retired address op
    for op in ["UABurn", "ZetherTransferSingle"] {
        let r = json!({"op": op, "env": {}, "payload": "0x", "proof": "0x", "beneficiary": "0x"});
        assert!(call("namedCall", &r.to_string()).is_err(), "{op}");
    }
}

/// Review E C-3: a corrupted leg count `M` in a multi payload is refused by name, never wrapped into a short length or a panic.
#[test]
fn named_call_refuses_a_corrupted_leg_count() {
    let v = vector();
    for op in ["UAZetherTransfer", "UAZetherTransferCompact"] {
        let good = named_req(&v, op, Value::Null);
        assert!(call("namedCall", &good.to_string()).is_ok(), "{op} positive control");
        let p = h(&good["payload"]);
        // M = 2^55: 512 · M wraps to 0 in 64 bits; M = 2^64 - 1; M one more than the legs given
        let legs = u64::from_be_bytes(p[136..144].try_into().unwrap());
        for m in [1u64 << 55, u64::MAX, legs + 1] {
            let mut q = p.clone();
            q[136..144].copy_from_slice(&m.to_be_bytes());
            let mut r = good.clone();
            r["payload"] = json!(format!("0x{}", hex::encode(&q)));
            let e = call("namedCall", &r.to_string()).unwrap_err();
            assert!(e.contains("not a multi transfer's"), "{op} M = {m}: {e}");
        }
    }
}

/// A derived subject (R35): `from` any `bytes32` id, signed by its own record's key through `requireAuthorized`; the digest is
/// `typedDigest`'s over the same message, and differs from the native row's. `from` as a 20-byte address is refused.
#[test]
fn named_call_takes_a_derived_from() {
    let v = vector();
    let derived = format!("0x{}", "7a".repeat(32));
    for op in NAMED {
        let row = &v["ops"][op];
        let mut r = named_req(&v, op, json!(null));
        r["env"]["from"] = json!(derived);
        let out = named(&r);
        assert_eq!(out["message"]["from"], json!(derived));
        let td: Value = serde_json::from_str(&call("typedDigest", &merge(req(row), json!({"op": op, "message": out["message"]})).to_string()).unwrap()).unwrap();
        assert_eq!(out["digest"], td["digest"], "{op}");
        assert_ne!(out["digest"], row["domains"]["zether"]["digest"], "{op}: from is signed");
        r["env"]["from"] = json!(format!("0x{}", "aa".repeat(20)));
        assert!(call("namedCall", &r.to_string()).unwrap_err().contains("`from` must be 32 bytes"), "{op}");
    }
}

/// `UASig` (TS-D12) with `keyData` and `members`: the entry's last parameter, against `cast abi-encode` (tools/env_ref.sh,
/// `ua_sig`); an empty one (no signature, no member) is refused, as no entry verifies it.
#[test]
fn named_call_encodes_a_full_ua_sig() {
    let v = vector();
    const CAST: &str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000001aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bbcc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001dd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ee00000000000000000000000000000000000000000000000000000000000000";
    let full = json!({"keyData": "0xaa", "signature": "0xbbcc", "members": [
        {"index": 1, "members": [{"index": 2, "sig": "0xdd"}], "sig": "0x"}, {"index": 3, "members": [], "sig": "0xee"}]});
    for op in NAMED {
        let row = &v["ops"][op];
        let want = h(&row["domains"]["zether"]["calldata"]);
        // `UASig` is the last parameter: its head word is the last of the head, its encoding the tail's end
        let got = h(&named(&named_req(&v, op, full.clone()))["calldata"]);
        let cast = hex::decode(CAST).unwrap();
        let (body, n) = (&cast[32..], cast.len() - 32);
        assert_eq!(&got[got.len() - n..], body, "{op}: UASig tail");
        // everything before it is the vector's calldata but the UASig's own encoding
        // the vector's `UASig{"", 65-byte signature, []}`: 3 head words, 3 length words, the signature in 3 words
        let vector_sig = 3 * 32 + 3 * 32 + 3 * 32;
        assert_eq!(&got[..got.len() - n], &want[..want.len() - vector_sig], "{op}: every parameter before UASig");
    }
    let err = call("namedCall", &named_req(&v, NAMED[0], json!({"keyData": "0xaa"})).to_string()).unwrap_err();
    assert!(err.contains("`sig` is required"), "{err}");
}
