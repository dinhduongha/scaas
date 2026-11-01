//! typed-signing C7: the Zether owner-op digests the prover builds equal the rows of smartcontracts/vectors/typed/typed_ops.json
//! (written by clients/clientkeys, checked against Foundry). The vector is the authority; nothing here is built from a test value.
use serde_json::{json, Value};

const OPS: [&str; 4] = ["ZetherRollOver", "ZetherSetRollOverMode", "UARollOverSigned", "UASetRollOverMode"];

#[test]
fn owner_digests_equal_typed_ops_rows() {
    let path = format!("{}/../../smartcontracts/vectors/typed/typed_ops.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for op in OPS {
        let row = &v["ops"][op];
        let dom = &row["domains"]["zether"];
        let req = json!({
            "op": op, "chainId": dom["domain"]["chainId"], "chainUid": dom["domain"]["salt"],
            "token": dom["domain"]["verifyingContract"], "message": row["message"],
        });
        let out: Value = serde_json::from_str(&zether_prover::api::call("ownerDigest", &req.to_string()).unwrap()).unwrap();
        assert_eq!(out["typehash"], row["typehash"], "{op} typehash");
        assert_eq!(out["structHash"], row["structHash"], "{op} structHash");
        assert_eq!(out["domainSeparator"], dom["domainSeparator"], "{op} domainSeparator");
        assert_eq!(out["digest"], dom["digest"], "{op} digest");
    }
}

#[test]
fn owner_digest_refuses_unknown_op_and_missing_field() {
    let base = json!({"chainId": 31337, "chainUid": format!("0x{}", "11".repeat(32)), "token": format!("0x{}", "22".repeat(20))});
    let call = |extra: Value| {
        let mut r = base.clone();
        r.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        zether_prover::api::call("ownerDigest", &r.to_string())
    };
    assert!(call(json!({"op": "Nope", "message": {}})).unwrap_err().contains("unknown owner op"));
    let short = json!({"op": "ZetherRollOver", "message": {"ua": format!("0x{}", "33".repeat(32))}});
    assert!(call(short).unwrap_err().contains("missing field `accSeq`"));
}
